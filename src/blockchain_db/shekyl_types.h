// Copyright (c) 2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause
//
// Strongly-typed identifiers and LMDB key/value encoders for Shekyl-specific
// curve-tree state. This header exists to make the following bug class
// unwritable:
//
//     uint64_t output_idx = ...;
//     db.get_curve_tree_leaf(output_idx, buf);   // was silently wrong: parameter
//                                                 // was actually tree position
//     db.get_curve_tree_leaf_by_tree_position(pos, buf);  // now explicit
//     db.get_curve_tree_leaf_by_output_index(idx, buf);   // double-lookup via mapping
//
// Every id that used to be a bare uint64_t in curve-tree code is now a
// distinct type with no implicit conversions. Passing the wrong kind is a
// compile error.
//
// Every LMDB composite key or structured value has a dedicated encoder with
// exactly one place where byte layout lives. Call sites never open-code
// byte packing.
//
// ─── Rust port note ────────────────────────────────────────────────────────
// These types are designed for 1:1 translation to Rust newtypes and heed
// BytesEncode/BytesDecode implementations during the V4 state-layer port.
// Do NOT extend this header to wrap MDB_txn, MDB_cursor, or the broader
// BlockchainDB interface — if the wrapper grows tentacles, the port cost
// grows nonlinearly. Keep this file to:
//   (1) StrongId<Tag> wrappers
//   (2) big-endian uint64 helpers
//   (3) key/value encoders for Shekyl-specific tables
// Nothing else belongs here.
// ───────────────────────────────────────────────────────────────────────────

#pragma once

#include <lmdb.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <stdexcept>
#include <vector>

#include "shekyl/consensus_constants_generated.h"

namespace shekyl { namespace db {

// ─── Big-endian uint64 primitives ──────────────────────────────────────────
//
// All composite keys use big-endian encoding so LMDB's default byte-wise
// comparison yields the canonical (high-order-field, low-order-field) sort
// order. Do NOT use native-endian here: on x86 that would reverse sort order
// and silently break the invariants the composite keys exist to enforce.

inline void store_be64(uint8_t* out, uint64_t v) noexcept
{
    for (int i = 7; i >= 0; --i) { out[i] = static_cast<uint8_t>(v); v >>= 8; }
}

inline uint64_t load_be64(const uint8_t* in) noexcept
{
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) { v = (v << 8) | in[i]; }
    return v;
}

inline void store_be32(uint8_t* out, uint32_t v) noexcept
{
    for (int i = 3; i >= 0; --i) { out[i] = static_cast<uint8_t>(v); v >>= 8; }
}

inline uint32_t load_be32(const uint8_t* in) noexcept
{
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) { v = (v << 8) | in[i]; }
    return v;
}

// ─── Strong identifiers ────────────────────────────────────────────────────
//
// Each Tag creates a distinct type. Passing OutputIndex where TreePosition
// is expected is a compile error. Access the underlying value via `.value`.
// Do NOT add implicit conversions, operator uint64_t, or non-explicit ctors
// — that would defeat the entire point.

template <typename Tag>
struct StrongId {
    uint64_t value;
    explicit constexpr StrongId(uint64_t v) noexcept : value(v) {}
    constexpr bool operator==(StrongId o) const noexcept { return value == o.value; }
    constexpr bool operator!=(StrongId o) const noexcept { return value != o.value; }
    constexpr bool operator<(StrongId o)  const noexcept { return value <  o.value; }
    constexpr bool operator<=(StrongId o) const noexcept { return value <= o.value; }
    constexpr bool operator>(StrongId o)  const noexcept { return value >  o.value; }
    constexpr bool operator>=(StrongId o) const noexcept { return value >= o.value; }
};

struct TreePositionTag   {};
struct OutputIndexTag    {};
struct MaturityHeightTag {};
struct BlockHeightTag    {};

// Position of a leaf within the curve tree (0-indexed, dense, monotonic).
// Assigned by drain_pending_tree_leaves in drain order. Used for tree layer
// traversal, path construction, and leaf-by-position lookup.
using TreePosition   = StrongId<TreePositionTag>;

// Global output index as assigned by Monero's output DB in block/tx scan
// order. Used for output metadata lookup and as the primary identifier in
// stake claims and wallet references. NOT equal to TreePosition in general.
using OutputIndex    = StrongId<OutputIndexTag>;

// Block height at which a pending output becomes eligible for insertion
// into the curve tree. Coinbase: h + 60. Regular: h + 10.
// Staked: max(effective_lock_until, h + 10).
using MaturityHeight = StrongId<MaturityHeightTag>;

// Block height (chain tip reference). Distinct from MaturityHeight
// because mixing them is a category error we want the compiler to catch.
using BlockHeight    = StrongId<BlockHeightTag>;

// ─── Sizes ─────────────────────────────────────────────────────────────────

static constexpr size_t kLeafSize            = 128; // 4 Selene scalars × 32B
static constexpr size_t kPendingLeafKeySize  = 16;  // BE(maturity) || BE(output)
static constexpr size_t kDrainKeySize        = 16;  // BE(block_height) || BE(output)
static constexpr size_t kDrainValueSize      = 136; // maturity[8] || leaf[128]
static constexpr size_t kBlockPendingKeySize = 16;  // BE(block_height) || BE(output_index)
static constexpr size_t kBlockPendingValSize = 8;   // maturity[8]
static constexpr size_t kArchivalServeCreditKeySize = 48; // P_id[32] || BE(shard) || BE(epoch)
static constexpr size_t kArchivalSlashLogKeySize = 12;    // BE(block_height) || BE(seq)
static constexpr uint32_t kArchivalSlashLogEpochMarkerSeq = 0xFFFFFFFFu;
static constexpr size_t kArchivalBondKeySize = 32;        // P_id[32]
static constexpr size_t kArchivalShardKeySize = 8;        // BE(shard_id)

// ─── Encoder lifetime contract ─────────────────────────────────────────────
//
// Every encoder class below exposes `as_mdb_val()` which returns an MDB_val
// whose `mv_data` points into the encoder object's own storage. The caller
// MUST keep the encoder alive for the full duration of the mdb_put/mdb_get/
// mdb_cursor_* call that uses the returned MDB_val.
//
// Do NOT call `as_mdb_val()` on a temporary:
//
//     MDB_val k = PendingLeafKey(m, o).as_mdb_val();   // WRONG: dangling
//     mdb_put(txn, dbi, &k, &v, 0);                    // use-after-free
//
//     PendingLeafKey key(m, o);                        // RIGHT
//     MDB_val k = key.as_mdb_val();
//     mdb_put(txn, dbi, &k, &v, 0);
//
// This is standard LMDB practice but is called out explicitly here because
// the whole point of this header is to make footguns unwritable, and a
// one-liner caveat is consistent with that philosophy.

// ─── PendingLeafKey ────────────────────────────────────────────────────────
//
// Key for m_pending_tree_leaves. Sorts by maturity first (so drain can break
// early), then by output_index within a maturity bucket (enforcing canonical
// insertion order by construction, replacing the DUPSORT-on-content design).

class PendingLeafKey {
public:
    PendingLeafKey(MaturityHeight m, OutputIndex o) noexcept
    {
        store_be64(bytes_.data(),     m.value);
        store_be64(bytes_.data() + 8, o.value);
    }

    static PendingLeafKey from_mdb_val(const MDB_val& v)
    {
        if (v.mv_size != kPendingLeafKeySize)
            throw std::runtime_error("PendingLeafKey: wrong mv_size");
        PendingLeafKey k;
        std::memcpy(k.bytes_.data(), v.mv_data, kPendingLeafKeySize);
        return k;
    }

    MDB_val as_mdb_val() const noexcept
    {
        return { bytes_.size(), const_cast<uint8_t*>(bytes_.data()) };
    }

    MaturityHeight maturity() const noexcept
    {
        return MaturityHeight{ load_be64(bytes_.data()) };
    }

    OutputIndex output() const noexcept
    {
        return OutputIndex{ load_be64(bytes_.data() + 8) };
    }

private:
    PendingLeafKey() = default;
    std::array<uint8_t, kPendingLeafKeySize> bytes_{};
};

// ─── DrainKey ──────────────────────────────────────────────────────────────
//
// Key for m_pending_tree_drain. Sorts by block_height (so pop_block can
// range-scan a single block's journal), then by output_index for
// deterministic replay order.

class DrainKey {
public:
    DrainKey(BlockHeight h, OutputIndex o) noexcept
    {
        store_be64(bytes_.data(),     h.value);
        store_be64(bytes_.data() + 8, o.value);
    }

    static DrainKey from_mdb_val(const MDB_val& v)
    {
        if (v.mv_size != kDrainKeySize)
            throw std::runtime_error("DrainKey: wrong mv_size");
        DrainKey k;
        std::memcpy(k.bytes_.data(), v.mv_data, kDrainKeySize);
        return k;
    }

    // For MDB_SET_RANGE cursor seeks to the first entry of a block.
    static DrainKey prefix(BlockHeight h) noexcept
    {
        return DrainKey(h, OutputIndex{0});
    }

    MDB_val as_mdb_val() const noexcept
    {
        return { bytes_.size(), const_cast<uint8_t*>(bytes_.data()) };
    }

    BlockHeight block_height() const noexcept
    {
        return BlockHeight{ load_be64(bytes_.data()) };
    }

    OutputIndex output() const noexcept
    {
        return OutputIndex{ load_be64(bytes_.data() + 8) };
    }

private:
    DrainKey() = default;
    std::array<uint8_t, kDrainKeySize> bytes_{};
};

// ─── DrainValue ────────────────────────────────────────────────────────────
//
// Value for m_pending_tree_drain. Contains everything pop_block needs to
// restore the pending entry without consulting any other table:
// the maturity (for re-insertion key) and the 128-byte leaf.
// output_index comes from the DrainKey, not the value.

class DrainValue {
public:
    DrainValue(MaturityHeight m, const uint8_t* leaf_data) noexcept
    {
        store_be64(bytes_.data(), m.value);
        std::memcpy(bytes_.data() + 8, leaf_data, kLeafSize);
    }

    static DrainValue from_mdb_val(const MDB_val& v)
    {
        if (v.mv_size != kDrainValueSize)
            throw std::runtime_error("DrainValue: wrong mv_size");
        DrainValue d;
        std::memcpy(d.bytes_.data(), v.mv_data, kDrainValueSize);
        return d;
    }

    MDB_val as_mdb_val() const noexcept
    {
        return { bytes_.size(), const_cast<uint8_t*>(bytes_.data()) };
    }

    MaturityHeight maturity() const noexcept
    {
        return MaturityHeight{ load_be64(bytes_.data()) };
    }

    const uint8_t* leaf() const noexcept
    {
        return bytes_.data() + 8;
    }

private:
    DrainValue() = default;
    std::array<uint8_t, kDrainValueSize> bytes_{};
};

// ─── BlockPendingKey / BlockPendingValue ───────────────────────────────────
//
// m_block_pending_additions journals the (maturity, output_index) of every
// output that was added to m_pending_tree_leaves by a given block. pop_block
// range-scans by block_height prefix and deletes the listed entries from
// m_pending_tree_leaves by primary key — eliminating the fragile
// reconstruction logic that computed output_ids from the post-pop state of
// Monero's output DB.
//
// Opened with MDB_CREATE only. Composite key BE(block_height)||BE(output)
// gives a stable deterministic iteration order under the default byte-
// compare. No DUPSORT anywhere in Shekyl curve-tree state — that rule is
// uniform across m_pending_tree_leaves, m_pending_tree_drain, and here.

class BlockPendingKey {
public:
    BlockPendingKey(BlockHeight h, OutputIndex o) noexcept
    {
        store_be64(bytes_.data(),     h.value);
        store_be64(bytes_.data() + 8, o.value);
    }

    static BlockPendingKey from_mdb_val(const MDB_val& v)
    {
        if (v.mv_size != kBlockPendingKeySize)
            throw std::runtime_error("BlockPendingKey: wrong mv_size");
        BlockPendingKey k;
        std::memcpy(k.bytes_.data(), v.mv_data, kBlockPendingKeySize);
        return k;
    }

    // For MDB_SET_RANGE cursor seeks to the first entry of a block.
    static BlockPendingKey prefix(BlockHeight h) noexcept
    {
        return BlockPendingKey(h, OutputIndex{0});
    }

    MDB_val as_mdb_val() const noexcept
    {
        return { bytes_.size(), const_cast<uint8_t*>(bytes_.data()) };
    }

    BlockHeight block_height() const noexcept
    {
        return BlockHeight{ load_be64(bytes_.data()) };
    }

    OutputIndex output() const noexcept
    {
        return OutputIndex{ load_be64(bytes_.data() + 8) };
    }

private:
    BlockPendingKey() = default;
    std::array<uint8_t, kBlockPendingKeySize> bytes_{};
};

class BlockPendingValue {
public:
    explicit BlockPendingValue(MaturityHeight m) noexcept
    {
        store_be64(bytes_.data(), m.value);
    }

    static BlockPendingValue from_mdb_val(const MDB_val& v)
    {
        if (v.mv_size != kBlockPendingValSize)
            throw std::runtime_error("BlockPendingValue: wrong mv_size");
        BlockPendingValue bpv;
        std::memcpy(bpv.bytes_.data(), v.mv_data, kBlockPendingValSize);
        return bpv;
    }

    MDB_val as_mdb_val() const noexcept
    {
        return { bytes_.size(), const_cast<uint8_t*>(bytes_.data()) };
    }

    MaturityHeight maturity() const noexcept
    {
        return MaturityHeight{ load_be64(bytes_.data()) };
    }

private:
    BlockPendingValue() = default;
    std::array<uint8_t, kBlockPendingValSize> bytes_{};
};

// ─── ArchivalServeCreditKey ────────────────────────────────────────────────
//
// Serve-credit ledger row: affirmative pass for (P_id, shard_id, E).
// Key existence is the authoritative bit; value is a 1-byte presence flag (gate-2 §3.1).

class ArchivalServeCreditKey {
public:
    ArchivalServeCreditKey(const uint8_t p_id[32], uint64_t shard_id, uint64_t settlement_epoch) noexcept
    {
        std::memcpy(bytes_.data(), p_id, 32);
        store_be64(bytes_.data() + 32, shard_id);
        store_be64(bytes_.data() + 40, settlement_epoch);
    }

    MDB_val as_mdb_val() const noexcept
    {
        return { bytes_.size(), const_cast<uint8_t*>(bytes_.data()) };
    }

private:
    std::array<uint8_t, kArchivalServeCreditKeySize> bytes_{};
};

// ─── ArchivalRMarketKey / ArchivalSigmaWorkKey (ARCHIVAL_CONSENSUS_STATE §3.3, §3.5)

static constexpr size_t kArchivalRMarketKeySize = 16;   // BE(shard_id) || BE(E)
static constexpr size_t kArchivalSigmaWorkKeySize = 8;   // BE(E)
static constexpr size_t kArchivalEpochCloseLogKeySize = 8; // BE(block_height)

class ArchivalRMarketKey {
public:
    ArchivalRMarketKey(uint64_t shard_id, uint64_t settlement_epoch) noexcept
    {
        store_be64(bytes_.data(), shard_id);
        store_be64(bytes_.data() + 8, settlement_epoch);
    }

    MDB_val as_mdb_val() const noexcept
    {
        return { bytes_.size(), const_cast<uint8_t*>(bytes_.data()) };
    }

private:
    std::array<uint8_t, kArchivalRMarketKeySize> bytes_{};
};

class ArchivalSigmaWorkKey {
public:
    explicit ArchivalSigmaWorkKey(uint64_t settlement_epoch) noexcept
    {
        store_be64(bytes_.data(), settlement_epoch);
    }

    MDB_val as_mdb_val() const noexcept
    {
        return { bytes_.size(), const_cast<uint8_t*>(bytes_.data()) };
    }

private:
    std::array<uint8_t, kArchivalSigmaWorkKeySize> bytes_{};
};

class ArchivalEpochCloseLogKey {
public:
    explicit ArchivalEpochCloseLogKey(uint64_t block_height) noexcept
    {
        store_be64(bytes_.data(), block_height);
    }

    MDB_val as_mdb_val() const noexcept
    {
        return { bytes_.size(), const_cast<uint8_t*>(bytes_.data()) };
    }

private:
    std::array<uint8_t, kArchivalEpochCloseLogKeySize> bytes_{};
};

// ─── ArchivalSlashLogKey / ArchivalSlashRevertValue ───────────────────────
//
// Per-block journal for gate-4 slash revert on `pop_block` (gate-2 §8).

class ArchivalSlashLogKey {
public:
    ArchivalSlashLogKey(uint64_t block_height, uint32_t seq) noexcept
    {
        store_be64(bytes_.data(), block_height);
        store_be32(bytes_.data() + 8, seq);
    }

    MDB_val as_mdb_val() const noexcept
    {
        return { bytes_.size(), const_cast<uint8_t*>(bytes_.data()) };
    }

private:
    std::array<uint8_t, kArchivalSlashLogKeySize> bytes_{};
};

struct ArchivalSlashRevertValue {
    // v2 (WS-1, REWARD_EMISSION_E3_GATING_ROUND.md §5) appends the pre-slash
    // holdings kind. v1 could not distinguish a complete-tree demotion (which
    // cleared *all* holdings) from a compact erase of a bond's last shard, so
    // (a) pop-revert restored the pre-image by an amount/emptiness heuristic
    // that mis-restores a slashed single-shard compact bond to complete-tree,
    // and (b) as-of-height holdings reconstruction from the log was ambiguous.
    // v1 is rejected at decode per the pre-genesis posture: no migration,
    // reset the data directory.
    static constexpr uint8_t kVersion = 2;
    static constexpr size_t kEncodedSize = 1 + 32 + 8 + 8 + 8 + 1;

    // Pre-slash holdings kind. Values mirror ArchivalBondValue's
    // kHoldingsShardSetCompact / kHoldingsCompleteTree (pinned by the
    // static_assert following that struct's definition below).
    static constexpr uint8_t kPreKindShardSetCompact = 0;
    static constexpr uint8_t kPreKindCompleteTree = 1;

    uint8_t p_id[32]{};
    uint64_t shard_id = 0;
    uint64_t settlement_epoch = 0;
    uint64_t slashed_amount = 0;
    /// Holdings kind of the bond *before* this slash applied. Complete-tree
    /// means the slash demoted the bond and cleared every holding (the bond
    /// held all shards at every height up to the slash); compact means the
    /// slash erased exactly `shard_id` from the held set.
    uint8_t holdings_pre_kind = kPreKindShardSetCompact;

    [[nodiscard]] std::vector<uint8_t> encode() const
    {
        if (holdings_pre_kind != kPreKindShardSetCompact
            && holdings_pre_kind != kPreKindCompleteTree)
        {
            throw std::runtime_error(
                "ArchivalSlashRevertValue encode: unknown holdings_pre_kind");
        }
        std::vector<uint8_t> out(kEncodedSize);
        out[0] = kVersion;
        std::memcpy(out.data() + 1, p_id, 32);
        for (int i = 7; i >= 0; --i)
            out[1 + 32 + (7 - i)] = static_cast<uint8_t>((shard_id >> (i * 8)) & 0xFF);
        for (int i = 7; i >= 0; --i)
            out[1 + 32 + 8 + (7 - i)] = static_cast<uint8_t>((settlement_epoch >> (i * 8)) & 0xFF);
        for (int i = 7; i >= 0; --i)
            out[1 + 32 + 16 + (7 - i)] = static_cast<uint8_t>((slashed_amount >> (i * 8)) & 0xFF);
        out[1 + 32 + 24] = holdings_pre_kind;
        return out;
    }

    static bool decode(const void* data, size_t len, ArchivalSlashRevertValue& out)
    {
        if (!data || len != kEncodedSize)
            return false;
        const auto* p = static_cast<const uint8_t*>(data);
        if (p[0] != kVersion)
            return false;
        std::memcpy(out.p_id, p + 1, 32);
        out.shard_id = load_be64(p + 33);
        out.settlement_epoch = load_be64(p + 41);
        out.slashed_amount = load_be64(p + 49);
        out.holdings_pre_kind = p[57];
        if (out.holdings_pre_kind != kPreKindShardSetCompact
            && out.holdings_pre_kind != kPreKindCompleteTree)
            return false;
        return true;
    }

    [[nodiscard]] bool is_epoch_marker() const noexcept
    {
        static const uint8_t zero[32] = {};
        return std::memcmp(p_id, zero, 32) == 0 && slashed_amount == 0;
    }
};

// ─── ArchivalBondKey ───────────────────────────────────────────────────────
//
// Gate-4 bond record keyed by P_canonical_id (ARCHIVAL_CONSENSUS_STATE.md §3.4).

class ArchivalBondKey {
public:
    explicit ArchivalBondKey(const uint8_t p_id[32]) noexcept
    {
        std::memcpy(bytes_.data(), p_id, 32);
    }

    MDB_val as_mdb_val() const noexcept
    {
        return { bytes_.size(), const_cast<uint8_t*>(bytes_.data()) };
    }

private:
    std::array<uint8_t, kArchivalBondKeySize> bytes_{};
};

// ─── ArchivalShardKey ──────────────────────────────────────────────────────
//
// Shard registry segment key (gate-2 §9). The challenge-path leaf chunk is
// read from the consensus curve-tree leaf table, not a shard-keyed snapshot
// (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §6.2).

class ArchivalShardKey {
public:
    explicit ArchivalShardKey(uint64_t shard_id) noexcept
    {
        store_be64(bytes_.data(), shard_id);
    }

    MDB_val as_mdb_val() const noexcept
    {
        return { bytes_.size(), const_cast<uint8_t*>(bytes_.data()) };
    }

private:
    std::array<uint8_t, kArchivalShardKeySize> bytes_{};
};

// ─── ArchivalBondValue ─────────────────────────────────────────────────────
//
// Versioned LMDB value for `archival_bond` (gate-4 §4; serve-credit reads).
//
// v4 (REWARD_EMISSION_LEG.md §6.2/§6.3, encoding pinned 2026-06-11) appends
// the windowed claimed-epoch set and `first_paying_emission_height`. v3 is
// rejected at decode per the pre-genesis posture: no migration, reset the
// data directory.

struct ArchivalBondValue {
    static constexpr uint8_t kVersion = 4;
    static constexpr uint8_t kHoldingsShardSetCompact = 0;
    static constexpr uint8_t kHoldingsCompleteTree = 1;
    static constexpr size_t kMaxPubkeyLen = 2048;
    static constexpr size_t kMaxHoldings = 4096;
    static constexpr size_t kMaxBadIntervals = 256;
    /// Claimed-epoch entry cap: claim window `W` plus reorg slack
    /// (REWARD_EMISSION_LEG.md §6.3 pins the cap at 32). Derived from the
    /// JSON authority so a `max_claim_age_w` change cannot drift past this
    /// codec; the static_assert below re-pins the §6.3 value and fires if
    /// the derivation and the pin ever disagree.
    static constexpr size_t kMaxClaimedEpochs =
        static_cast<size_t>(SHEKYL_ARCHIVAL_MAX_CLAIM_AGE_W) + 6;
    static_assert(kMaxClaimedEpochs == 32,
        "REWARD_EMISSION_LEG.md §6.3 pins the claimed-epoch cap at 32 "
        "(W = 26 + 6 reorg slack); revisit the pin if max_claim_age_w moves");

    struct BadInterval {
        uint64_t start_epoch = 0;
        uint64_t end_exclusive = 0; // UINT64_MAX = open-ended bad standing
    };

    std::vector<uint8_t> hybrid_pubkey;
    uint64_t join_settlement_epoch = 0;
    /// Per-P bonded balance (gate-4 §4.1); must equal `bond_floor(holdings)` post-connect.
    uint64_t bonded_total_atomic = 0;
    /// `kHoldingsShardSetCompact` or `kHoldingsCompleteTree` (gate-4 §3.4.1).
    uint8_t holdings_kind = kHoldingsShardSetCompact;
    std::vector<uint64_t> held_shard_ids;
    std::vector<BadInterval> bad_intervals;
    /// Strictly increasing absolute settlement-epoch indices already claimed
    /// by an emission vin (REWARD_EMISSION_LEG.md §6.3). Empty at join. The
    /// dedup semantics — windowed `check_and_set` that prunes entries below
    /// `current_settled_epoch − W` on insert — are consensus semantics and
    /// live in Rust only (`shekyl-archival-retention::claimed_epochs`); this
    /// codec stores and validates the at-rest shape (cap, order, span).
    std::vector<uint64_t> claimed_settlement_epochs;
    /// Height of the first emission that paid this `P` (REWARD_EMISSION_LEG.md
    /// §6.2; set-once, immutable after first write — the emission PR is the
    /// only writer). Sentinel 0 = unset: unreachable as a real value because
    /// no emission can pay before the first settlement epoch closes at height
    /// `SETTLEMENT_EPOCH_BLOCKS` (10_000).
    uint64_t first_paying_emission_height = 0;

    [[nodiscard]] bool is_complete_tree() const noexcept
    {
        return holdings_kind == kHoldingsCompleteTree;
    }

    [[nodiscard]] std::vector<uint8_t> encode() const
    {
        if (hybrid_pubkey.size() > kMaxPubkeyLen
            || held_shard_ids.size() > kMaxHoldings
            || bad_intervals.size() > kMaxBadIntervals
            || claimed_settlement_epochs.size() > kMaxClaimedEpochs)
        {
            throw std::runtime_error("ArchivalBondValue encode: bounds exceeded");
        }
        // decode() rejects any holdings_kind outside the two known values, so a
        // serializer that accepted them would persist a record no read path can
        // decode. Reject here to keep encode/decode symmetric — a write that
        // round-trips is the at-rest contract, surfaced loudly rather than
        // deferred to the next scan's decode failure.
        if (holdings_kind != kHoldingsShardSetCompact
            && holdings_kind != kHoldingsCompleteTree)
        {
            throw std::runtime_error("ArchivalBondValue encode: unknown holdings_kind");
        }
        // The claimed set's order and span invariants are maintained by the
        // Rust dedup helper; a violation here is a writer bug, surfaced loudly
        // rather than deferred to the next decode.
        if (!claimed_epochs_well_formed())
            throw std::runtime_error(
                "ArchivalBondValue encode: claimed_settlement_epochs order/span violated");

        std::vector<uint8_t> out;
        out.reserve(1 + 2 + hybrid_pubkey.size() + 8 + 8 + 1 + 4 + held_shard_ids.size() * 8
            + 4 + bad_intervals.size() * 16 + 4 + claimed_settlement_epochs.size() * 8 + 8);
        out.push_back(kVersion);
        const uint16_t pk_len = static_cast<uint16_t>(hybrid_pubkey.size());
        out.push_back(static_cast<uint8_t>(pk_len >> 8));
        out.push_back(static_cast<uint8_t>(pk_len));
        out.insert(out.end(), hybrid_pubkey.begin(), hybrid_pubkey.end());
        for (int i = 7; i >= 0; --i)
            out.push_back(static_cast<uint8_t>((join_settlement_epoch >> (i * 8)) & 0xFF));
        for (int i = 7; i >= 0; --i)
            out.push_back(static_cast<uint8_t>((bonded_total_atomic >> (i * 8)) & 0xFF));
        out.push_back(holdings_kind);
        const uint32_t holdings_count = static_cast<uint32_t>(held_shard_ids.size());
        for (int i = 3; i >= 0; --i)
            out.push_back(static_cast<uint8_t>((holdings_count >> (i * 8)) & 0xFF));
        for (const uint64_t shard_id : held_shard_ids)
        {
            for (int i = 7; i >= 0; --i)
                out.push_back(static_cast<uint8_t>((shard_id >> (i * 8)) & 0xFF));
        }
        const uint32_t interval_count = static_cast<uint32_t>(bad_intervals.size());
        for (int i = 3; i >= 0; --i)
            out.push_back(static_cast<uint8_t>((interval_count >> (i * 8)) & 0xFF));
        for (const BadInterval& iv : bad_intervals)
        {
            for (int i = 7; i >= 0; --i)
                out.push_back(static_cast<uint8_t>((iv.start_epoch >> (i * 8)) & 0xFF));
            for (int i = 7; i >= 0; --i)
                out.push_back(static_cast<uint8_t>((iv.end_exclusive >> (i * 8)) & 0xFF));
        }
        const uint32_t claimed_count = static_cast<uint32_t>(claimed_settlement_epochs.size());
        for (int i = 3; i >= 0; --i)
            out.push_back(static_cast<uint8_t>((claimed_count >> (i * 8)) & 0xFF));
        for (const uint64_t epoch : claimed_settlement_epochs)
        {
            for (int i = 7; i >= 0; --i)
                out.push_back(static_cast<uint8_t>((epoch >> (i * 8)) & 0xFF));
        }
        for (int i = 7; i >= 0; --i)
            out.push_back(static_cast<uint8_t>((first_paying_emission_height >> (i * 8)) & 0xFF));
        return out;
    }

    /// True when the claimed set satisfies the §6.3 at-rest invariants:
    /// strictly increasing, and spanning no more than `W` from oldest to
    /// newest (the windowed dedup helper prunes below `current − W`, so a
    /// wider span cannot arise from a correct writer).
    [[nodiscard]] bool claimed_epochs_well_formed() const noexcept
    {
        for (size_t i = 1; i < claimed_settlement_epochs.size(); ++i)
        {
            if (claimed_settlement_epochs[i] <= claimed_settlement_epochs[i - 1])
                return false;
        }
        if (!claimed_settlement_epochs.empty()
            && claimed_settlement_epochs.back() - claimed_settlement_epochs.front()
                > SHEKYL_ARCHIVAL_MAX_CLAIM_AGE_W)
        {
            return false;
        }
        return true;
    }

    static bool decode(const void* data, size_t len, ArchivalBondValue& out)
    {
        if (!data || len < 1 + 2 + 8 + 8 + 1 + 4 + 4 + 4 + 8)
            return false;
        const auto* p = static_cast<const uint8_t*>(data);
        size_t off = 0;
        const uint8_t version = p[off++];
        if (version != kVersion)
            return false;
        if (off + 2 > len)
            return false;
        const uint16_t pk_len = static_cast<uint16_t>((p[off] << 8) | p[off + 1]);
        off += 2;
        if (pk_len > kMaxPubkeyLen || off + pk_len + 8 + 8 + 1 > len)
            return false;
        out.hybrid_pubkey.assign(p + off, p + off + pk_len);
        off += pk_len;
        out.join_settlement_epoch = load_be64(p + off);
        off += 8;
        out.bonded_total_atomic = load_be64(p + off);
        off += 8;
        out.holdings_kind = p[off++];
        if (out.holdings_kind != kHoldingsShardSetCompact
            && out.holdings_kind != kHoldingsCompleteTree)
        {
            return false;
        }
        if (off + 4 > len)
            return false;
        const uint32_t holdings_count = static_cast<uint32_t>(
            (static_cast<uint32_t>(p[off]) << 24)
            | (static_cast<uint32_t>(p[off + 1]) << 16)
            | (static_cast<uint32_t>(p[off + 2]) << 8)
            | static_cast<uint32_t>(p[off + 3]));
        off += 4;
        if (holdings_count > kMaxHoldings || off + holdings_count * 8u + 4 > len)
            return false;
        out.held_shard_ids.clear();
        out.held_shard_ids.reserve(holdings_count);
        for (uint32_t i = 0; i < holdings_count; ++i)
        {
            out.held_shard_ids.push_back(load_be64(p + off));
            off += 8;
        }
        const uint32_t interval_count = static_cast<uint32_t>(
            (static_cast<uint32_t>(p[off]) << 24)
            | (static_cast<uint32_t>(p[off + 1]) << 16)
            | (static_cast<uint32_t>(p[off + 2]) << 8)
            | static_cast<uint32_t>(p[off + 3]));
        off += 4;
        if (interval_count > kMaxBadIntervals || off + interval_count * 16u + 4 > len)
            return false;
        out.bad_intervals.clear();
        out.bad_intervals.reserve(interval_count);
        for (uint32_t i = 0; i < interval_count; ++i)
        {
            BadInterval iv{};
            iv.start_epoch = load_be64(p + off);
            off += 8;
            iv.end_exclusive = load_be64(p + off);
            off += 8;
            out.bad_intervals.push_back(iv);
        }
        const uint32_t claimed_count = static_cast<uint32_t>(
            (static_cast<uint32_t>(p[off]) << 24)
            | (static_cast<uint32_t>(p[off + 1]) << 16)
            | (static_cast<uint32_t>(p[off + 2]) << 8)
            | static_cast<uint32_t>(p[off + 3]));
        off += 4;
        if (claimed_count > kMaxClaimedEpochs || off + claimed_count * 8u + 8 != len)
            return false;
        out.claimed_settlement_epochs.clear();
        out.claimed_settlement_epochs.reserve(claimed_count);
        for (uint32_t i = 0; i < claimed_count; ++i)
        {
            out.claimed_settlement_epochs.push_back(load_be64(p + off));
            off += 8;
        }
        if (!out.claimed_epochs_well_formed())
            return false;
        out.first_paying_emission_height = load_be64(p + off);
        off += 8;
        return true;
    }

    // good_through(P, E) is consensus semantics and lives in Rust only
    // (shekyl-archival-retention::good_through, via shekyl_archival_good_through).

    [[nodiscard]] bool holds_shard(uint64_t shard_id) const noexcept
    {
        if (is_complete_tree())
            return true;
        for (const uint64_t held : held_shard_ids)
        {
            if (held == shard_id)
                return true;
        }
        return false;
    }
};

// The slash log's pre-image kind field copies the bond's holdings_kind byte
// verbatim (apply writes `bond.holdings_kind` pre-mutation); pin the two
// enums together so neither can drift.
static_assert(ArchivalSlashRevertValue::kPreKindShardSetCompact
        == ArchivalBondValue::kHoldingsShardSetCompact
    && ArchivalSlashRevertValue::kPreKindCompleteTree
        == ArchivalBondValue::kHoldingsCompleteTree,
    "slash-log holdings_pre_kind must mirror ArchivalBondValue holdings_kind");

// ─── ArchivalShardSegmentValue ─────────────────────────────────────────────

struct ArchivalShardSegmentValue {
    static constexpr uint8_t kVersion = 1;

    uint64_t freeze_height = 0;
    uint64_t segment_leaf_count = 0;
    std::array<uint8_t, 32> segment_subroot_rk{};

    [[nodiscard]] std::vector<uint8_t> encode() const
    {
        std::vector<uint8_t> out(1 + 8 + 8 + 32);
        out[0] = kVersion;
        store_be64(out.data() + 1, freeze_height);
        store_be64(out.data() + 9, segment_leaf_count);
        std::memcpy(out.data() + 17, segment_subroot_rk.data(), 32);
        return out;
    }

    static bool decode(const void* data, size_t len, ArchivalShardSegmentValue& out)
    {
        if (!data || len != 1 + 8 + 8 + 32)
            return false;
        const auto* p = static_cast<const uint8_t*>(data);
        if (p[0] != kVersion)
            return false;
        out.freeze_height = load_be64(p + 1);
        out.segment_leaf_count = load_be64(p + 9);
        std::memcpy(out.segment_subroot_rk.data(), p + 17, 32);
        return true;
    }
};

// ─── Mapping-table helpers (single-uint64 key and value) ───────────────────
//
// m_output_to_leaf: OutputIndex  → TreePosition
// m_leaf_to_output: TreePosition → OutputIndex
//
// Both opened with MDB_INTEGERKEY. The U64Key helper wraps a native-endian
// uint64_t in an MDB_val. Lifetime rule is the same as the composite-key
// encoders above: the U64Key must outlive the mdb_put/mdb_get call.

struct U64Key {
    uint64_t v;
    explicit U64Key(uint64_t x) noexcept : v(x) {}
    // MDB_INTEGERKEY expects native-endian uint64_t in memory.
    // const_cast matches the pattern used by the composite-key encoders;
    // harmless because LMDB never writes through mv_data on put/get.
    MDB_val as_mdb_val() const noexcept
    {
        return { sizeof(v), const_cast<uint64_t*>(&v) };
    }
};

} } // namespace shekyl::db

// ─── std::hash specializations ─────────────────────────────────────────────
//
// Enables use of the strong-id types as keys in unordered containers.
// Not strictly required by the current fix, but cheap to provide and
// avoids a footgun when someone later reaches for std::unordered_map.

namespace std {
template <typename Tag>
struct hash<shekyl::db::StrongId<Tag>> {
    size_t operator()(shekyl::db::StrongId<Tag> id) const noexcept {
        return std::hash<uint64_t>{}(id.value);
    }
};
} // namespace std
