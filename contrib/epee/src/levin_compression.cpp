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

// Marshaling shim over the shekyl_levin_* FFI (rule 20: the boundary
// advanced; the codec, its policy constants, and the safety caps live in
// rust/shekyl-levin/src/compress.rs). This file owns no compression logic
// and links no libzstd — the Rust image carries the single copy.

#include "net/levin_compression.h"

#include "misc_log_ex.h"
#include "shekyl/shekyl_ffi.h"

namespace epee
{
namespace levin
{
namespace
{
  //! Human-readable cause for an FFI return code. The receive path closes
  //! the connection on every failure, so the code is the only thing that
  //! tells an operator whether they are looking at a hostile peer or an
  //! honest one whose batch outgrew a cap — responses that are opposite.
  const char* levin_rc_reason(const int32_t rc) noexcept
  {
    switch (rc)
    {
    case -3: return "malformed frame or missing declared content size";
    case -4: return "null pointer or undersized output buffer";
    case -6: return "the linked Rust image has no zstd support";
    case -7: return "size limit exceeded";
    default: return "unknown failure";
    }
  }
} // anonymous

  bool compress_payload(epee::span<const uint8_t> input, std::string& output)
  {
    ShekylBuffer buf{};
    const int32_t rc = shekyl_levin_compress_payload(input.data(), input.size(), &buf);
    if (rc != 0)
    {
      // Contract: false leaves `output` empty (callers may reuse the string).
      // rc == 1 is "declined — send it uncompressed", the expected outcome
      // for small or incompressible payloads; only negative codes are bugs.
      output.clear();
      if (rc < 0)
        MERROR("Levin payload compression failed: " << levin_rc_reason(rc) << " (rc=" << rc << ")");
      return false;
    }
    // Compression is the one direction that still hands back a Rust
    // allocation: its output size is not knowable before the fact.
    if (buf.ptr == nullptr || buf.len == 0)
      output.clear();
    else
      output.assign(reinterpret_cast<const char*>(buf.ptr), buf.len);
    shekyl_buffer_free(buf.ptr, buf.len);
    return true;
  }

  bool decompress_payload(epee::span<const uint8_t> input, std::string& output,
                          const uint64_t max_output)
  {
    // Two steps on purpose. The first validates the frame's *declared*
    // content size against the caller's limit before anything is sized from
    // it, so a frame that lies cannot cost an allocation; the second
    // inflates straight into this string's storage. Nothing is allocated on
    // the Rust side and nothing is copied across the boundary — during IBD
    // these are multi-megabyte block batches, once per packet per
    // connection.
    std::size_t inflated = 0;
    int32_t rc = shekyl_levin_inflated_size(input.data(), input.size(), max_output, &inflated);
    if (rc != 0)
    {
      // Contract: false leaves `output` empty (callers may reuse the string).
      output.clear();
      MERROR("Levin payload decompression rejected: " << levin_rc_reason(rc) << " (rc=" << rc << ")");
      return false;
    }

    output.resize(inflated);
    std::size_t written = 0;
    rc = shekyl_levin_decompress_into(input.data(), input.size(),
                                      reinterpret_cast<uint8_t*>(output.empty() ? nullptr : &output[0]),
                                      output.size(), &written);
    if (rc != 0)
    {
      output.clear();
      MERROR("Levin payload decompression failed: " << levin_rc_reason(rc) << " (rc=" << rc << ")");
      return false;
    }
    // `shekyl_levin_decompress_into` rejects any frame that does not deliver
    // exactly the declared size, so this cannot shrink the string; it is
    // here so the postcondition is stated where the buffer is handed on.
    output.resize(written);
    return true;
  }

} // levin
} // epee
