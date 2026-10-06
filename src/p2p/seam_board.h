// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A copy of the seam board a walk can hold.
//!
//! `shekyl_seam_board` hands the rows to the visit for that call only.
//! The vector this header builds is the snapshot the walk keeps. A later
//! publish does not change it. A count is `shekyl_seam_board_count`, not
//! a scan of this copy. The handshake flag is not part of that count.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "p2p/seam_endpoint.h"
#include "shekyl/shekyl_ffi.h"

namespace shekyl
{
  extern "C" inline void seam_board_assign(void* ctx, const shekyl_seam_board_row* rows, std::size_t count)
  {
    auto* out = static_cast<std::vector<shekyl_seam_board_row>*>(ctx);
    out->clear();
    if (rows != nullptr && count != 0)
      out->insert(out->end(), rows, rows + count);
  }

  /// The bound process hub's rows. Empty when no hub is bound.
  inline std::vector<shekyl_seam_board_row> seam_board_snapshot()
  {
    std::vector<shekyl_seam_board_row> rows;
    if (shekyl_seam_board(&rows, seam_board_assign) != 0)
      rows.clear();
    return rows;
  }
}
