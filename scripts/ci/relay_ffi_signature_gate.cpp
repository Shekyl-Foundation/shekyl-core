// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//
// The relay-FFI signature gate TU (scripts/ci/check_relay_ffi_signatures.sh).
//
// C linkage erases types: a hand-written declaration that drifts from its
// Rust definition compiles, links by name alone, and is UB at runtime — the
// hazard docs/FOLLOWUPS.md registers for src/shekyl/shekyl_ffi.h. A
// link-only probe cannot catch this (the Rust side never enters that
// compilation; refuted on the record in the FOLLOWUPS entry). This TU can:
// it includes the hand-written header and then a cbindgen-generated
// declarations-only header derived from the Rust definitions. extern "C"
// functions cannot overload, so any disagreement in arity, parameter types,
// or return type is a conflicting-declaration COMPILE error — the C++
// compiler performs the comparison, and both inputs to it derive from the
// artifacts under test.
//
// Negative-controlled at introduction (both injected into a copy of the
// hand-written header and observed to fail): dropping a parameter from
// shekyl_relay_zone_poll -> "conflicting declaration of C function";
// changing now_ms from uint64_t to uint32_t -> same error class.
//
// Order matters: the hand-written header comes first so its type
// definitions (ShekylRelayBlob, the callback typedefs, the #define flag
// values) exist before the generated declarations reference them.

#include "shekyl/shekyl_ffi.h"

#include "shekyl_ffi_generated_relay.h"

int main()
{
  return 0;
}
