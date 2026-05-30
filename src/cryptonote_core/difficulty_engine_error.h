// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/// @file difficulty_engine_error.h
/// @brief Typed exception thrown by the LWMA-1 difficulty bridge.
///
/// The inherited `next_difficulty(...)` function in
/// `src/cryptonote_basic/difficulty.{h,cpp}` was infallible (returned a
/// difficulty value unconditionally). LWMA-1 Phase 4 replaces the call
/// sites with the FFI shim `shekyl_difficulty_lwma1_next` which returns
/// an `int32_t` error code; the non-zero codes signal consensus-invariant
/// violations (NULL_PTR, INVALID_COUNT, OVERFLOW) that the daemon treats
/// as fatal.
///
/// The bridge in `blockchain.cpp` translates a non-zero FFI return into
/// this exception. Callers catch it by type if they need to distinguish
/// DAA failures from other `std::runtime_error` instances (e.g., for
/// structured logging), or let it propagate to the daemon top-level
/// crash handler.
///
/// The Rust workspace builds with `panic = "abort"`; the FFI shim itself
/// cannot panic across the boundary. The only paths that surface a
/// non-zero error code are the explicit consensus-invariant checks in
/// `shekyl_difficulty_lwma1_next` — see
/// `rust/shekyl-ffi/src/difficulty_ffi.rs`.

#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>

#include "shekyl/shekyl_ffi.h"  // SHEKYL_DIFFICULTY_ERR_* macros

namespace cryptonote
{

/// Thrown by the LWMA-1 bridge when `shekyl_difficulty_lwma1_next`
/// returns a non-zero error code. The numeric `code()` matches one of
/// the `SHEKYL_DIFFICULTY_ERR_*` macros defined in `shekyl/shekyl_ffi.h`.
class difficulty_computation_error : public std::runtime_error
{
public:
    explicit difficulty_computation_error(std::int32_t code)
        : std::runtime_error(format_message(code))
        , m_code(code)
    {
    }

    /// The raw `SHEKYL_DIFFICULTY_ERR_*` discriminant.
    std::int32_t code() const noexcept { return m_code; }

private:
    std::int32_t m_code;

    static std::string format_message(std::int32_t code)
    {
        switch (code)
        {
            case SHEKYL_DIFFICULTY_ERR_NULL_PTR:
                return "LWMA-1 FFI: null pointer";
            case SHEKYL_DIFFICULTY_ERR_INVALID_COUNT:
                return "LWMA-1 FFI: invalid count "
                       "(consensus invariant violation)";
            case SHEKYL_DIFFICULTY_ERR_OVERFLOW:
                return "LWMA-1 FFI: arithmetic overflow "
                       "(consensus invariant violation)";
            case SHEKYL_DIFFICULTY_ERR_INTERNAL:
                return "LWMA-1 FFI: internal failure";
            default:
                return "LWMA-1 FFI: unknown error code "
                     + std::to_string(code);
        }
    }
};

} // namespace cryptonote
