// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Daemon-only operator shard-fetch scheduler (`ARCHIVAL_SHARD_FETCH.md` SF-D1).
/// Lives outside `shekyl_ffi.h`: `shekyl-p-fetch` must not enter `shekyl-ffi`
/// (`scripts/ci/check_p_fetch_dep_cut.py`). The sole definition is
/// `shekyl-archival-fetch-sched` via `shekyl-daemon-image` (daemon and
/// unit_tests both select that image). A C++ weak stub in `rpc` would
/// win GNU ld's first-archive pass and pin production on typed MISS.
///
/// Every node prunes. Shard bodies below the window live with stakers, or
/// temporarily on a daemon that requested the shard to view. This entry is
/// that view-fetch (and a local hold/view-cache, when those land). A freeze
/// row is not a body.

#define SHEKYL_DAEMON_SHARD_FETCH_OK 0
#define SHEKYL_DAEMON_SHARD_FETCH_MISS 1

typedef struct ShekylArchivalShardAggregateOut {
  uint64_t shard_id;
  uint8_t shard_hash[32];
  uint64_t block_count;
  uint64_t tx_count;
  uint64_t output_count;
  uint64_t coinbase_output_count;
  uint64_t time_range_seconds;
} ShekylArchivalShardAggregateOut;

uint8_t shekyl_daemon_operator_shard_fetch(
    uint64_t shard_id, ShekylArchivalShardAggregateOut* out);

#ifdef __cplusplus
}
#endif
