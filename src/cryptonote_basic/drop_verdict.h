// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#pragma once

#include "cryptonote_basic/verification_context.h"
#include "shekyl/shekyl_ffi.h"

namespace cryptonote
{
  /// PWD-B7 write path. Folds `incoming` into `slot` through the Rust type.
  /// A null `slot` is a no-op (callers with no peer pass null).
  inline void classify_drop(uint8_t *slot, uint8_t incoming)
  {
    shekyl_drop_verdict_classify(slot, incoming);
  }

  inline void classify_drop(tx_verification_context &tvc, uint8_t incoming)
  {
    shekyl_drop_verdict_classify(&tvc.m_drop_verdict, incoming);
  }

  /// Classify and return false. Does not touch the other tvc flags; the
  /// caller sets those before returning.
  inline bool reject_form(tx_verification_context &tvc)
  {
    classify_drop(tvc, SHEKYL_DROP_VERDICT_ATTRIBUTABLE_FORM);
    return false;
  }

  inline bool reject_state(tx_verification_context &tvc)
  {
    classify_drop(tvc, SHEKYL_DROP_VERDICT_POLICY_OR_STATE);
    return false;
  }

  inline bool reject_internal(tx_verification_context &tvc)
  {
    classify_drop(tvc, SHEKYL_DROP_VERDICT_INTERNAL_FAILURE);
    return false;
  }
}
