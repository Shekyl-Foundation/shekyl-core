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
  //! Copy an FFI buffer into `output` and free the Rust allocation.
  void take_buffer(ShekylBuffer& buf, std::string& output)
  {
    output.assign(reinterpret_cast<const char*>(buf.ptr), buf.len);
    shekyl_buffer_free(buf.ptr, buf.len);
  }
} // anonymous

  bool is_compression_available() noexcept
  {
    return shekyl_levin_compression_available();
  }

  bool compress_payload(epee::span<const uint8_t> input, std::string& output)
  {
    ShekylBuffer buf{};
    const int32_t rc = shekyl_levin_compress_payload(input.data(), input.size(), &buf);
    if (rc != 0)
    {
      // rc == 1 is "declined — send it uncompressed", the expected outcome
      // for small or incompressible payloads; only negative codes are bugs.
      if (rc < 0)
        MERROR("Levin payload compression failed, rc=" << rc);
      return false;
    }
    take_buffer(buf, output);
    return true;
  }

  bool decompress_payload(epee::span<const uint8_t> input, std::string& output,
                          const uint64_t max_output)
  {
    ShekylBuffer buf{};
    const int32_t rc =
        shekyl_levin_decompress_payload(input.data(), input.size(), max_output, &buf);
    if (rc != 0)
    {
      MERROR("Levin payload decompression failed, rc=" << rc);
      return false;
    }
    take_buffer(buf, output);
    return true;
  }

} // levin
} // epee
