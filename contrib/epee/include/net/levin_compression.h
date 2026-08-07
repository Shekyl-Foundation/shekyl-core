// Copyright (c) 2025-2026, The Shekyl Foundation
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

#include <cstdint>
#include <string>

#include "span.h"

namespace epee
{
namespace levin
{
  // Marshaling shim over the `shekyl_levin_*` FFI (src/shekyl/shekyl_ffi.h,
  // rust/shekyl-ffi/src/levin_ffi.rs): the Rust-pinned libzstd is the single
  // zstd implementation in the binary, and the compression policy constants
  // (256-byte minimum payload, level 1, 128 MiB decompression cap) are
  // single-sourced in rust/shekyl-levin/src/compress.rs. No system libzstd
  // is linked and there is no HAVE_ZSTD build gate; availability is a
  // property of the linked Rust image.
  //
  // Only the receive half lives here. The emit half is whole-message and is
  // `epee::levin::try_compress_message` in levin_base.h, itself a shim over
  // `shekyl_levin_compress_message` — there is no C++ payload-level compress
  // entry point, because every question that decides whether a buffer may be
  // compressed is about its bucket header.

  //! Decompress one Levin COMPRESSED payload. `max_output` bounds the
  //! declared content size *before any allocation*; pass the packet-size
  //! limit the bucket header was checked against — the same
  //! min(packet limit, per-command cap) the bucket header itself is checked
  //! against, which is what makes the bound on an inflated payload
  //! identical to the bound on an uncompressed one. Returns false on a
  //! malformed, size-less, or oversized frame (connection-fatal for the
  //! caller), logging which of those it was. On false, `output` is cleared
  //! (safe for callers that reuse the string).
  //!
  //! Inflation writes directly into `output` — no intermediate buffer, no
  //! copy across the FFI boundary.
  bool decompress_payload(epee::span<const uint8_t> input, std::string& output,
                          uint64_t max_output);

} // levin
} // epee
