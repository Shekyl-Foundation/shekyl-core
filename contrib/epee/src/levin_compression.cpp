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

#include "net/levin_compression.h"

#include "misc_log_ex.h"

#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

namespace epee
{
namespace levin
{
  bool is_compression_available() noexcept
  {
#ifdef HAVE_ZSTD
    return true;
#else
    return false;
#endif
  }

  bool compress_payload(epee::span<const uint8_t> input, std::string& output)
  {
#ifdef HAVE_ZSTD
    if (input.size() < COMPRESSION_MIN_PAYLOAD)
      return false;

    const size_t bound = ZSTD_compressBound(input.size());
    if (ZSTD_isError(bound))
      return false;

    output.resize(bound);
    const size_t compressed_size = ZSTD_compress(
        output.data(), bound,
        input.data(), input.size(),
        ZSTD_COMPRESSION_LEVEL);

    if (ZSTD_isError(compressed_size))
    {
      MERROR("zstd compression failed: " << ZSTD_getErrorName(compressed_size));
      output.clear();
      return false;
    }

    if (compressed_size >= input.size())
    {
      output.clear();
      return false;
    }

    output.resize(compressed_size);
    return true;
#else
    (void)input;
    (void)output;
    return false;
#endif
  }

  bool decompress_payload(epee::span<const uint8_t> input, std::string& output)
  {
#ifdef HAVE_ZSTD
    const unsigned long long decompressed_size = ZSTD_getFrameContentSize(input.data(), input.size());
    if (decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN || decompressed_size == ZSTD_CONTENTSIZE_ERROR)
    {
      MERROR("zstd decompression: cannot determine content size");
      return false;
    }
    if (decompressed_size > DECOMPRESSED_MAX_SIZE)
    {
      MERROR("zstd decompression: frame claims " << decompressed_size << " bytes, exceeds limit");
      return false;
    }

    output.resize(static_cast<size_t>(decompressed_size));
    const size_t actual = ZSTD_decompress(output.data(), output.size(), input.data(), input.size());
    if (ZSTD_isError(actual))
    {
      MERROR("zstd decompression failed: " << ZSTD_getErrorName(actual));
      output.clear();
      return false;
    }

    output.resize(actual);
    return true;
#else
    (void)input;
    (void)output;
    MERROR("Received compressed Levin payload but zstd support was not compiled in");
    return false;
#endif
  }

} // levin
} // epee
