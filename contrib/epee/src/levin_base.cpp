// Copyright (c) 2019-2022, The Monero Project
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

#include "net/levin_base.h"

#include "byte_slice.h"
#include "byte_stream.h"
#include "int-util.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "shekyl/shekyl_ffi.h"

#include <cstring>

namespace epee
{
namespace levin
{
  message_writer::message_writer(const std::size_t reserve)
    : buffer()
  {
    buffer.reserve(reserve);
    buffer.put_n(0, sizeof(header));
  }

  byte_slice message_writer::finalize(const uint32_t command, const uint32_t flags, const uint32_t return_code, const bool expect_response)
  {
    if (buffer.size() < sizeof(header))
      throw std::runtime_error{"levin_writer::finalize already called"};

    header head = make_header(command, payload_size(), flags, expect_response);
    head.m_return_code = SWAP32LE(return_code);

    std::memcpy(buffer.tellp() - buffer.size(), std::addressof(head), sizeof(head));
    return byte_slice{std::move(buffer)};
  }

  bucket_head2 make_header(uint32_t command, uint64_t msg_size, uint32_t flags, bool expect_response) noexcept
  {
    bucket_head2 head = {0};
    head.m_signature = SWAP64LE(LEVIN_SIGNATURE);
    head.m_have_to_return_data = expect_response;
    head.m_cb = SWAP64LE(msg_size);

    head.m_command = SWAP32LE(command);
    head.m_protocol_version = SWAP32LE(LEVIN_PROTOCOL_VER_1);
    head.m_flags = SWAP32LE(flags);
    return head;
  }

  namespace
  {
    //! Copy a Rust-allocated FFI buffer into a byte_slice, freeing it on
    //! *every* exit — reserve/write can throw (std::bad_alloc), and the
    //! connection machinery catches and survives handler exceptions, so a
    //! throw would otherwise leak the buffer rather than end the process.
    byte_slice adopt_ffi_buffer(ShekylBuffer& buf)
    {
      const auto buf_guard = misc_utils::create_scope_leave_handler(
          [&buf] { shekyl_buffer_free(buf.ptr, buf.len); });

      byte_stream out;
      out.reserve(buf.len);
      out.write(buf.ptr, buf.len);
      return byte_slice{std::move(out)};
    }
  } // anonymous

  // Forwarding shim over shekyl_levin_compress_message (rule 20). Every
  // decision — is this already compressed, is it exactly one message, is it
  // the noise/fragment class whose constant on-wire size is the point of
  // it, is the payload worth compressing, is the result actually smaller —
  // and the header rewrite itself live in rust/shekyl-levin. This function
  // holds no policy; it converts buffers.
  //
  // The seam moved up from compress_payload to the whole message because
  // most of those questions are about the bucket header, and a
  // payload-level seam left them stranded here as a second, weaker copy:
  // the C++ this replaces checked neither the signature, nor that the
  // header accounted for every byte after it, nor the noise class.
  byte_slice try_compress_message(byte_slice input)
  {
    const auto data = to_span(input);
    ShekylBuffer buf{};
    // Declined (rc == 1) is the ordinary outcome and means "send it as it
    // is"; the caller keeps ownership of `input` either way.
    if (shekyl_levin_compress_message(data.data(), data.size(), &buf) != 0)
      return input;

    return adopt_ffi_buffer(buf);
  }

  // Forwarding shim over shekyl_levin_noise_notify (rule 20): the noise
  // shape — command 0, B|E, zeroed body, exact total size — lives in
  // rust/shekyl-levin, where the read side that discards it already lives.
  // Invalid sizes come back as a null slice, the historical contract.
  byte_slice make_noise_notify(const std::size_t noise_bytes)
  {
    ShekylBuffer buf{};
    if (shekyl_levin_noise_notify(noise_bytes, &buf) != 0)
      return nullptr;

    return adopt_ffi_buffer(buf);
  }

  // Forwarding shim over shekyl_levin_fragmented_notify (rule 20). The
  // pad-to-noise-or-fragment decision, the B/middle/E header sequence, and
  // the padding discipline — the privacy-load-bearing piece, since constant
  // on-wire size is the entire property white-noise buys — now have exactly
  // one implementation, in rust/shekyl-levin. Only the writer's payload
  // bytes cross; the inner notification header is rebuilt byte-identically
  // on the Rust side from (command, payload).
  byte_slice make_fragmented_notify(const std::size_t noise_size, const int command, message_writer message)
  {
    if (message.buffer.size() < sizeof(bucket_head2))
      return nullptr; // finalize already consumed the writer

    ShekylBuffer buf{};
    if (shekyl_levin_fragmented_notify(noise_size, static_cast<uint32_t>(command),
                                       message.buffer.data() + sizeof(bucket_head2),
                                       message.payload_size(), &buf) != 0)
      return nullptr;

    return adopt_ffi_buffer(buf);
  }
} // levin
} // epee
