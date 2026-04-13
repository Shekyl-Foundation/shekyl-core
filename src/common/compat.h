// Copyright (c) 2024-2026, The Shekyl Foundation
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

// Centralized platform-compatibility shims.
// Include this header instead of scattering #ifdef _WIN32 / _MSC_VER
// guards around POSIX headers in every translation unit.

// --- ssize_t ---
#if defined(_MSC_VER) && !defined(ssize_t)
#include <basetsd.h>
typedef SSIZE_T ssize_t;
#endif

// --- unistd.h (POSIX) vs io.h (MSVC) ---
#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

// --- dlfcn.h (POSIX dynamic loader) ---
#if !defined(_WIN32) && !defined(STATICLIB)
#include <dlfcn.h>
#endif

// --- sys/mman.h (POSIX memory mapping) ---
#if !defined(_WIN32) && !defined(__MINGW32__)
#include <sys/mman.h>
#endif
