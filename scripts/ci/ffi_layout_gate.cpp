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
// (#[repr(C)]) and again by hand in a C header under src/. A hand-written
// definition whose members moved compiles, links, and reads one field out
// of another's bytes. A size check alone does not see two members of one
// width swapped.
//
// This TU includes the hand-written headers, then the Rust definitions
// cbindgen generated, one namespace per crate (array bounds first, from the
// crates that own them), then the static_asserts ffi_layout_gate.py wrote
// for each pair its GROUPS list names: size, alignment, and each member's
// offset and type, members keyed by name. The script has already compared
// the member names in order, both ways, so a member one side lacks fails
// there, even one that fits in the other side's padding.
//
// A member type is compared after mapping each generated struct to its
// hand-written twin (norm below), so a pointer to, or an embedded, crossing
// struct compares as the twin it is, and an enum as its underlying integer.
//
// Negative-controlled at introduction (TSR-F1, PR #1092), each injected into
// a header, a Rust source or the manifest and observed to fail the gate. In
// shekyl_seam_handshake_result: current_height and cumulative_difficulty
// swapped (one width, so the size agrees) -> member-name compare;
// support_flags widened to uint64_t -> size and type; _pad dropped, top_id
// renamed, and a member only the header has carved out of _pad -> each the
// member-name compare; alignas on a member -> the script refuses a
// declaration it cannot read. TOR_HOST_MAX changed to 63 in shekyl-seam ->
// size and type of shekyl_seam_address, so the bound is Rust's own. In
// shekyl_rpc_tx_entry: pruned_flag widened -> size and offset; `where`
// renamed in C -> member-name compare; the manifest's rename naming a member
// Rust lacks -> refused. shekyl_rpc_sync_span_facts::remote_address typed
// uint8_t* -> type. A new struct in rpc_facts_ffi.h with no pair -> the
// completeness scan.
//
// At introduction the gate also found divergences in the tree, fixed in the
// same change: ShekylStemTallyRow's padding was `pad` in the C header and
// `_pad` in Rust (the header now says `_pad`; no C++ reads it), and six text
// members C++ reads as char were u8 in Rust: ShekylBanView::text,
// ShekylRpcPeerFacts::host, and daemon-rpc's ConnectionFactsFfi::address and
// ::host, SyncSpanFactsFfi::remote_address and PeerFactsFfi::host. Rust now
// declares them c_char.

#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "shekyl_ffi_layout_c.h"

#include "shekyl_ffi_layout_rust.h"

namespace ffi_layout_gate {

// A member's Rust type, with each crossing struct replaced by its twin and
// each enum by its underlying integer.
template <class T, bool = std::is_enum<T>::value> struct scalar { using type = T; };
template <class T> struct scalar<T, true> { using type = std::underlying_type_t<T>; };
template <class T> struct norm { using type = typename scalar<T>::type; };
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
