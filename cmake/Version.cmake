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

# Development-build fallback when not building from a tag or tarball.
# Update this before branching a new major/minor release series.
set(SHEKYL_VERSION_DEFAULT "3.1.0")

# This file is the one home of the build identity (DAEMON_CONFIG_CUTOVER.md
# DC-Q20): the version, its tag, whether the build is a release, and the
# release name. `src/version.cpp.in` reads them for the C++ `version`
# library; `cmake/BuildRust.cmake` passes SHEKYL_VERSION_FULL,
# SHEKYL_RELEASE_NAME and SHEKYL_VERSION_IS_RELEASE to every cargo-built
# binary, where `rust/shekyl-version` reads them. Neither side spells a
# value of its own.
set(SHEKYL_RELEASE_NAME "Shekyl NG" CACHE STRING "The release name" FORCE)

function (write_version tag)
  set(VERSIONTAG "${tag}" CACHE STRING "The tag portion of the Shekyl software version" FORCE)
  # One spelling. version.cpp.in and the cargo invocations both read
  # this; neither concatenates the version and the tag itself.
  set(SHEKYL_VERSION_FULL "${SHEKYL_VERSION}-${tag}" CACHE STRING "Shekyl version and tag, hyphenated" FORCE)
  set(SHEKYL_VERSION_IS_RELEASE "${VERSION_IS_RELEASE}" CACHE STRING "true for a tarball or tagged build" FORCE)
  configure_file("${CMAKE_CURRENT_LIST_DIR}/../src/version.cpp.in" "${CMAKE_BINARY_DIR}/version.cpp")
endfunction ()

find_package(Git QUIET)
if ("$Format:$" STREQUAL "")
  # Tarball build -- no git metadata available, use hardcoded default.
  set(SHEKYL_VERSION "${SHEKYL_VERSION_DEFAULT}" CACHE STRING "Shekyl version" FORCE)
  set(VERSION_IS_RELEASE "true")
  write_version("release")
elseif (GIT_FOUND OR Git_FOUND)
  message(STATUS "Found Git: ${GIT_EXECUTABLE}")
  include(GitVersion)
  get_version_tag_from_git("${GIT_EXECUTABLE}")
  # Use tag-derived version when available, otherwise the dev default.
  if(NOT SHEKYL_VERSION)
    set(SHEKYL_VERSION "${SHEKYL_VERSION_DEFAULT}")
  endif()
  set(SHEKYL_VERSION "${SHEKYL_VERSION}" CACHE STRING "Shekyl version" FORCE)
  message(STATUS "Shekyl version: ${SHEKYL_VERSION}")
  write_version("${VERSIONTAG}")
else()
  message(STATUS "WARNING: Git was not found!")
  set(SHEKYL_VERSION "${SHEKYL_VERSION_DEFAULT}" CACHE STRING "Shekyl version" FORCE)
  set(VERSION_IS_RELEASE "false")
  write_version("unknown")
endif ()
add_custom_target(genversion ALL
  DEPENDS "${CMAKE_BINARY_DIR}/version.cpp")
