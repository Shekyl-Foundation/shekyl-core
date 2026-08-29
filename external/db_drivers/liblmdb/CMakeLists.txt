# Copyright (c) 2014-2019, The Monero Project
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

if(FREEBSD)
  add_definitions(-DMDB_DSYNC=O_SYNC)
endif()

if(ANDROID)
  add_definitions("-DANDROID=1")
endif()


set (lmdb_sources
mdb.c
midl.c)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

add_library(lmdb
  ${lmdb_sources})
target_link_libraries(lmdb
  PRIVATE
    ${CMAKE_THREAD_LIBS_INIT})
# GUI/libwallet install target
if (BUILD_GUI_DEPS)
    if(IOS)
        set(lib_folder lib-${ARCH})
    else()
        set(lib_folder lib)
    endif()
    install(TARGETS lmdb
        ARCHIVE DESTINATION ${lib_folder}
        LIBRARY DESTINATION ${lib_folder})
endif()
set_property(TARGET lmdb PROPERTY POSITION_INDEPENDENT_CODE ON)

# Offline LMDB compaction (`shekyl-mdb-copy -c <src> <dst>`), built from the
# vendored upstream utility. This is the schema-agnostic replacement for the
# retired schema-aware copy tool: the daemon prunes in place, and compaction
# needs no knowledge of the table set.
add_executable(mdb_copy mdb_copy.c)
target_link_libraries(mdb_copy
  PRIVATE
    lmdb
    ${CMAKE_THREAD_LIBS_INIT})
set_target_properties(mdb_copy
  PROPERTIES
    OUTPUT_NAME "shekyl-mdb-copy"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
install(TARGETS mdb_copy DESTINATION bin)
