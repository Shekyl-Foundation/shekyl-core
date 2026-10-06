// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A copy of the seam board a walk can hold.
//!
//! `shekyl_seam_board` visits one fixed-size row per call. The pointer is
//! valid only for that call. A missing hub, or a board with no rows,
//! visits once with a null row, and this assign ignores it. The vector
//! starts empty, so that visit leaves the snapshot empty. A later publish
//! does not change the copy. A count is `shekyl_seam_board_count`, not a
//! scan of this copy. The handshake flag is not part of that count.

#pragma once

#include <vector>

#include "p2p/seam_endpoint.h"
#include "shekyl/shekyl_ffi.h"

namespace shekyl
{
  extern "C" inline void seam_board_assign(void* ctx, const shekyl_seam_board_row* row)
  {
    if (row == nullptr)
      return;
    auto* out = static_cast<std::vector<shekyl_seam_board_row>*>(ctx);
    out->push_back(*row);
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
