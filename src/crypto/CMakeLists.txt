# Copyright (c) 2014-2022, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

set(crypto_hash_sources
  blake256.c
  groestl.c
  hash.c
  hash-extra-blake.c
  hash-extra-groestl.c
  hash-extra-jh.c
  hash-extra-skein.c
  hmac-keccak.c
  jh.c
  keccak.c
  skein.c
  tree-hash.c)

set(crypto_ops_sources
  aesb.c
  crypto-ops-data.c
  crypto-ops.c
  oaes_lib.c
  random.c)

set(crypto_slowhash_sources
  slow-hash.c)

set(crypto_rx_sources
  rx-slow-hash.c)

# CryptonightR_JIT.c contains x86 JIT code that is entirely dead on MSVC
# (returns -1).  Its heavyweight includes trigger an MSVC ICE in the PDB
# type server (CloseTypeServerPDB, confirmed on 14.44 and 14.50).  Use a
# minimal stub on MSVC that provides the same -1 return path.
set(crypto_jit_sources)
if(MSVC)
  list(APPEND crypto_jit_sources CryptonightR_JIT_stub.c)
else()
  list(APPEND crypto_jit_sources CryptonightR_JIT.c)
  if(ARCH_ID STREQUAL "i386" OR ARCH_ID STREQUAL "x86_64" OR ARCH_ID STREQUAL "x86-64" OR ARCH_ID STREQUAL "amd64")
    list(APPEND crypto_jit_sources CryptonightR_template.S)
  endif()
endif()

set(crypto_cpp_sources
  crypto.cpp
  generators.cpp
  pow_cryptonight.cpp
  pow_randomx.cpp
  pow_registry.cpp)

include_directories(${RANDOMX_INCLUDE})

set(crypto_headers)

monero_find_all_headers(crypto_private_headers "${CMAKE_CURRENT_SOURCE_DIR}")

# Split into small OBJECT libraries.  On MSVC this avoids an ICE in the PDB
# type server (CloseTypeServerPDB); on other compilers it's harmless.
monero_private_headers(cncrypto
  ${crypto_private_headers})

set(_cncrypto_obj_targets)
foreach(_group hash ops slowhash rx jit cpp)
  set(_target obj_cncrypto_${_group})
  add_library(${_target} OBJECT
    ${crypto_${_group}_sources} ${crypto_headers} ${crypto_private_headers})
  target_compile_definitions(${_target}
    PRIVATE $<TARGET_PROPERTY:cncrypto,INTERFACE_COMPILE_DEFINITIONS>)
  if(MSVC)
    target_compile_options(${_target} PRIVATE /MP1)
  endif()
  list(APPEND _cncrypto_obj_targets $<TARGET_OBJECTS:${_target}>)
endforeach()

add_library(cncrypto ${_cncrypto_obj_targets})
set_property(TARGET cncrypto PROPERTY FOLDER "libs")

target_link_libraries(cncrypto
  PUBLIC
    epee
    randomx
    ${Boost_SYSTEM_LIBRARY}
    ${SODIUM_LIBRARY}
  PRIVATE
    ${EXTRA_LIBRARIES})

if (ARM)
  option(NO_OPTIMIZED_MULTIPLY_ON_ARM
	   "Compute multiply using generic C implementation instead of ARM ASM" OFF)
  if(NO_OPTIMIZED_MULTIPLY_ON_ARM)
    message(STATUS "Using generic C implementation for multiply")
    set_property(SOURCE slow-hash.c
      PROPERTY COMPILE_DEFINITIONS "NO_OPTIMIZED_MULTIPLY_ON_ARM")
  endif()
endif()

# Because of the way Qt works on android with JNI, the code does not live in the main android thread
# So this code runs with a 1 MB default stack size. 
# This will force the use of the heap for the allocation of the scratchpad
if (ANDROID OR IOS)
  if( BUILD_GUI_DEPS )
    add_definitions(-DFORCE_USE_HEAP=1)
  endif()
endif()

# cheat because cmake and ccache hate each other
set_property(SOURCE CryptonightR_template.S PROPERTY LANGUAGE C)
set_property(SOURCE CryptonightR_template.S PROPERTY XCODE_EXPLICIT_FILE_TYPE sourcecode.asm)

# Must be done last, because it references libraries in this directory
add_subdirectory(wallet)
