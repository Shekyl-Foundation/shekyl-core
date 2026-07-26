// Copyright (c) 2026, The Shekyl Foundation
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

#pragma once

#include <cstddef>
#include <cstdint>

// C ABI for the Dandelion++ stem map. The map logic lives in
// shekyl-relay-privacy's `StemMap`; the C++ `net::dandelionpp::connection_map`
// forwards to these once its own logic is removed (RP-2a,
// docs/design/DAEMON_RELAY_PRIVACY.md §16). The Rust side owns a
// cryptographically-secure RNG; every id is a 16-byte Boost UUID (a nil UUID —
// all zero — is the absent-slot / local-origin sentinel). Every call is
// serialised by the zone strand, so the handle needs no internal lock.
//
// Rust twins: rust/shekyl-ffi/src/dandelionpp_ffi.rs.

// Opaque handle to the Rust `StemMap`. Never dereferenced on the C++ side.
struct StemMapHandle;

extern "C"
{
    //! Construct a map over `ids` (`n` × 16 bytes), keeping at most `stems`
    //! slots. Release with `shekyl_dandelionpp_map_free`.
    StemMapHandle* shekyl_dandelionpp_map_new(const std::uint8_t* ids, std::size_t n, std::size_t stems);

    //! Deep-copy a handle (the C++ copy-constructor / `clone()`); the copy and
    //! original share nothing. Release the result with `..._free`.
    StemMapHandle* shekyl_dandelionpp_map_clone(const StemMapHandle* handle);

    //! Merge `ids` (`n` × 16 bytes) into the map. Returns true iff the live stem
    //! set changed — the re-arm predicate, not "the set differed".
    bool shekyl_dandelionpp_map_update(StemMapHandle* handle, const std::uint8_t* ids, std::size_t n);

    //! Resolve the stem for `source` (16 bytes; nil = local origin) into `out`
    //! (16 bytes). Returns true if a stem was assigned; on false `out` is nil.
    bool shekyl_dandelionpp_map_get_stem(StemMapHandle* handle, const std::uint8_t* source, std::uint8_t* out);

    //! Copy every slot in index order (nil for an empty slot) into `buf`
    //! (`cap` × 16 bytes); returns the slot count. If `cap` is below the count,
    //! nothing is written and the needed count is returned (size with cap 0).
    std::size_t shekyl_dandelionpp_map_snapshot(const StemMapHandle* handle, std::uint8_t* buf, std::size_t cap);

    //! Number of slots backed by a live peer (the C++ `size()` non-nil count).
    std::size_t shekyl_dandelionpp_map_live_stems(const StemMapHandle* handle);

    //! Free a handle. Null is a no-op; free exactly once.
    void shekyl_dandelionpp_map_free(StemMapHandle* handle);
}
