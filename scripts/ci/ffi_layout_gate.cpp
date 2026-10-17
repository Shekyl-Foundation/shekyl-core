// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//
// The struct-layout TU of the FFI signature gate
// (scripts/ci/check_ffi_signatures.sh).
//
// The signature limb (ffi_signature_gate.cpp) compares declarations, and a
// struct crossing the boundary is not a declaration: it is defined in Rust
// (#[repr(C)]) and again by hand in src/shekyl/shekyl_ffi.h. A hand-written
// definition whose members moved compiles, links, and reads one field out
// of another's bytes. A size check alone does not see two members of one
// width swapped.
//
// This TU includes the hand-written header, then the Rust definitions
// cbindgen generated into namespace rust_layout (array bounds first, from
// the crates that own them), then the static_asserts ffi_layout_gate.py
// wrote for each pair the gate's LAYOUTS list names: size, alignment, and
// each member's offset and type, members keyed by name. The script has
// already compared the member names in order, both ways, so a member one
// side lacks fails there, even one that fits in the other side's padding.
//
// A member type is compared after mapping each rust_layout struct to its
// hand-written twin (norm below), so a pointer to, or an embedded,
// crossing struct compares as the twin it is.
//
// Negative-controlled at introduction (TSR-F1, PR #1092), each injected into
// the header or a Rust source and observed to fail the gate. In
// shekyl_seam_handshake_result: current_height and cumulative_difficulty
// swapped (one width, so the size agrees) -> member-name compare;
// support_flags widened to uint64_t -> size, type, and the next member's
// offset; _pad dropped -> member-name compare; top_id renamed ->
// member-name compare; a member only the header has, carved out of _pad ->
// member-name compare; alignas on a member -> the script refuses a
// declaration it cannot read. TOR_HOST_MAX changed to 63 in shekyl-seam ->
// size and type of shekyl_seam_address and shekyl_seam_observed, so the
// bound is Rust's own. SHEKYL_SEAM_HOST_MAX changed in the header -> the
// header's own static_asserts. And at introduction the gate found three
// real divergences: ShekylStemTallyRow's padding was named pad in C and
// _pad in Rust, and ShekylBanView::text and ShekylRpcPeerFacts::host were
// u8 in Rust and char in C, which C++ reads as text; Rust now declares
// them c_char.

#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "shekyl/shekyl_ffi.h"

#include "shekyl_ffi_layout_bounds.h"
#include "shekyl_ffi_layout_rust.h"

namespace ffi_layout_gate {

// A member's Rust type, with each crossing struct replaced by its twin.
template <class T> struct norm { using type = T; };
template <class T> struct norm<T*> { using type = typename norm<T>::type*; };
template <class T> struct norm<const T> { using type = const typename norm<T>::type; };
template <class T, std::size_t N> struct norm<T[N]> { using type = typename norm<T>::type[N]; };
template <class T, std::size_t N> struct norm<const T[N]> { using type = const typename norm<T>::type[N]; };

template <class R, class C>
constexpr bool same = std::is_same<typename norm<R>::type, C>::value;

}  // namespace ffi_layout_gate

#include "shekyl_ffi_layout_asserts.h"

int main()
{
  return 0;
}
