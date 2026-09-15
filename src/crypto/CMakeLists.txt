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
  hash.c
  hmac-keccak.c
  keccak.c
  tree-hash.c)

set(crypto_ops_sources
  crypto-ops-data.c
  crypto-ops.c
  random.c)

set(crypto_cpp_sources
  crypto.cpp
  generators.cpp
  pow_randomx.cpp)

set(crypto_headers)

monero_find_all_headers(crypto_private_headers "${CMAKE_CURRENT_SOURCE_DIR}")

# Split into small OBJECT libraries.  On MSVC this avoids an ICE in the PDB
# type server (CloseTypeServerPDB); on other compilers it's harmless.
monero_private_headers(cncrypto
  ${crypto_private_headers})

set(_cncrypto_obj_targets)
foreach(_group hash ops cpp)
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
    ${Boost_SYSTEM_LIBRARY}
    ${SODIUM_LIBRARY}
  PRIVATE
    ${EXTRA_LIBRARIES})

# Must be done last, because it references libraries in this directory
add_subdirectory(wallet)
