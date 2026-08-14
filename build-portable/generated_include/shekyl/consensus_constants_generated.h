// @generated from consensus_constants.json by cmake/generate_consensus_constants.py
// Do not edit manually. The JSON file is the single source of truth.
#pragma once

// `<stdint.h>` is the canonical home of the `UINT*_C` fixed-width
// literal macros (C99 §7.18.4). C++11 §17.6.1.2 also requires that
// `<cstdint>` expose them, but including the C header explicitly is
// the belt-and-suspenders form that does not depend on the standard
// library implementation honouring that guarantee on every platform
// Shekyl is built for. Both headers are kept so the emitted file
// works whether consumers use `std::uint8_t` or `uint8_t`.
#include <cstdint>
#include <stdint.h>

// Values bracketed `SHEKYL_*` to make their generated origin obvious at
// every consumer; original symbols (`FCMP_REFERENCE_BLOCK_MIN_AGE`,
// `FCMP_REFERENCE_BLOCK_MAX_AGE`, `CTTypeFcmpPlusPlusPqc`) are now
// `static_assert`-pinned to these. The emitted fixed-width literal
// macros (`UINT8_C` / `UINT64_C`) are validated against the declared
// type's range at generator time, so a JSON value that overflows
// (e.g. `ct_type_fcmp_plus_plus_pqc` > 255) fails the build at
// CMake configure rather than truncating silently.
#define SHEKYL_FCMP_REFERENCE_BLOCK_MIN_AGE     UINT64_C(5)
#define SHEKYL_FCMP_REFERENCE_BLOCK_MAX_AGE     UINT64_C(100)
#define SHEKYL_CT_TYPE_FCMP_PLUS_PLUS_PQC     UINT8_C(1)

// LWMA-1 difficulty adjustment parameters per docs/completed/DAA_LWMA1.md
// §4. Generated alongside the FCMP/CT constants because both subsets
// share the cross-language-drift threat model (Bug 3 of the 2026-05-05
// audit). The Rust mirror lives in rust/shekyl-difficulty's build.rs;
// the Phase 4 C++ cutover replaces inherited `DIFFICULTY_TARGET_V2`,
// `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT`, and
// `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW` with the symbols below per
// docs/completed/DAA_LWMA1_PLAN.md Phase 4. Until Phase 4 lands, these
// macros are emitted but have no C++ consumer.
#define SHEKYL_DAA_WINDOW_N     UINT64_C(90)
#define SHEKYL_DAA_TARGET_SECONDS     UINT64_C(120)
#define SHEKYL_DAA_FTL_SECONDS     UINT64_C(540)
#define SHEKYL_DAA_MTP_WINDOW     UINT64_C(11)
#define SHEKYL_DAA_GENESIS_DIFFICULTY     UINT64_C(100)

// Archival per-shard retention bond floor (ARCHIVAL_BOND_FLOOR). Emitted
// alongside the FCMP/DAA constants because genesis foundation identities and
// market archiver registration consume the same cross-language authority.
// Rust mirror: rust/shekyl-engine-core/build.rs. Until the C++ archival
// registry lands, this macro has no C++ consumer.
#define SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC     UINT64_C(750000000)

// Archival claim-age window `W` (MAX_CLAIM_AGE_W,
// ARCHIVAL_TIMING_CONSTANTS.md §1; REWARD_EMISSION_LEG.md §6.6). Emission
// for settlement epoch E is rejected once E < C - W; the windowed
// ClaimedEpochSet on ArchivalBondValue derives its decode invariants
// (entry cap W + reorg slack, span <= W) from this value. Rust mirror:
// rust/shekyl-archival-retention/build.rs (MAX_CLAIM_AGE_W).
#define SHEKYL_ARCHIVAL_MAX_CLAIM_AGE_W     UINT64_C(26)

// Segment/shard geometry (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §5.2):
// SEGMENT_LEAF_COUNT, the level-2 subtree leaf count under the
// production curve-tree widths (38 * 18 * 38 = 25992). C++ consumes
// this macro ONLY as the registry row's segment_leaf_count value field
// in the freeze writer; the first-crossing boundary division lives
// solely in the Rust entry point (shekyl_archival_frozen_segment_count)
// and the division-one-site tripwire refuses `/`/`%` spellings against
// this macro in src/. Rust mirror + width-product compile assert:
// rust/shekyl-archival-retention (segment_freeze.rs).
#define SHEKYL_ARCHIVAL_SEGMENT_LEAF_COUNT     UINT64_C(25992)

// Per-shard retention-commitment horizon (gate-4 §4.4;
// ARCHIVAL_TIMING_CONSTANTS.md §1). Shape genesis-frozen (age-scaled-constant:
// bond_duration(age) = BASE * (1 + SCALE * age), age = shard_age_milli @ the
// shard's add-epoch settlement close); numerics provisional (H2 plateau arm,
// re-pin at testnet within scale band [2,8]). Consumer is Rust-only at genesis
// (bond-FSM verify, shekyl-archival-retention::bond_duration); mirror in
// rust/shekyl-archival-retention/build.rs. Emitted for cross-language parity,
// no C++ consumer yet.
#define SHEKYL_BOND_DURATION_BASE_EPOCHS     UINT64_C(4)
#define SHEKYL_BOND_DURATION_AGE_SCALE     UINT64_C(4)
