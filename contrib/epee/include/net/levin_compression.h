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
  // These are marshaling shims over the `shekyl_levin_*` FFI
  // (src/shekyl/shekyl_ffi.h, rust/shekyl-ffi/src/levin_ffi.rs): the
  // Rust-pinned libzstd is the single zstd implementation in the binary,
  // and the compression policy constants (256-byte minimum payload,
  // level 1, 128 MiB decompression cap) are single-sourced in
  // rust/shekyl-levin/src/compress.rs. No system libzstd is linked and
  // there is no HAVE_ZSTD build gate; availability is a property of the
  // linked Rust image.

  //! Compress one Levin payload. Returns false meaning "send it
  //! uncompressed" (below the minimum, not smaller compressed, or
  //! compression unavailable) — not an error.
  bool compress_payload(epee::span<const uint8_t> input, std::string& output);

  //! Decompress one Levin COMPRESSED payload. `max_output` bounds the
  //! declared content size *before any allocation*; pass the packet-size
  //! limit the bucket header was checked against. Returns false on a
  //! malformed, size-less, or oversized frame (connection-fatal for the
  //! caller).
  bool decompress_payload(epee::span<const uint8_t> input, std::string& output,
                          uint64_t max_output);

  //! Whether the linked Rust image can compress/decompress.
  bool is_compression_available() noexcept;

} // levin
} // epee
