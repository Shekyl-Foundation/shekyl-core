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

set(crypto_core_sources
  aesb.c
  chacha.c
  crypto-ops-data.c
  crypto-ops.c
  crypto.cpp
  generators.cpp
  oaes_lib.c
  random.c
  pow_cryptonight.cpp
  pow_randomx.cpp
  pow_registry.cpp
  slow-hash.c
  rx-slow-hash.c
  CryptonightR_JIT.c)

if(ARCH_ID STREQUAL "i386" OR ARCH_ID STREQUAL "x86_64" OR ARCH_ID STREQUAL "x86-64" OR ARCH_ID STREQUAL "amd64")
list(APPEND crypto_core_sources CryptonightR_template.S)
endif()

include_directories(${RANDOMX_INCLUDE})

set(crypto_headers)

monero_find_all_headers(crypto_private_headers "${CMAKE_CURRENT_SOURCE_DIR}")

# MSVC 14.44 ICE (C1001) during "Generating Code..." when all crypto sources
# are in a single OBJECT library.  The crash is in CloseTypeServerPDB -- the
# shared PDB type server chokes on the combined type records.  Splitting into
# two smaller OBJECT libraries keeps each below the threshold.
# On non-MSVC compilers we still use the split (harmless) for simplicity.
monero_private_headers(cncrypto
  ${crypto_private_headers})

add_library(obj_cncrypto_hash OBJECT
  ${crypto_hash_sources} ${crypto_headers} ${crypto_private_headers})
add_library(obj_cncrypto_core OBJECT
  ${crypto_core_sources} ${crypto_headers} ${crypto_private_headers})

target_compile_definitions(obj_cncrypto_hash
  PRIVATE $<TARGET_PROPERTY:cncrypto,INTERFACE_COMPILE_DEFINITIONS>)
target_compile_definitions(obj_cncrypto_core
  PRIVATE $<TARGET_PROPERTY:cncrypto,INTERFACE_COMPILE_DEFINITIONS>)

if(MSVC)
  target_compile_options(obj_cncrypto_hash PRIVATE /MP1)
  target_compile_options(obj_cncrypto_core PRIVATE /MP1)
endif()

add_library(cncrypto
  $<TARGET_OBJECTS:obj_cncrypto_hash>
  $<TARGET_OBJECTS:obj_cncrypto_core>)
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
