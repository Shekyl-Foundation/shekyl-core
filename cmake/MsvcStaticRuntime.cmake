# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The MSVC C runtime Shekyl links. Included from the top-level
# CMakeLists.txt, before add_subdirectory(external): CMP0091 copies
# CMAKE_MSVC_RUNTIME_LIBRARY onto a target when the target is created,
# so a value set afterwards would leave external/ on the dynamic default
# and src/ on the static runtime.
#
# Two spellings of one choice.
#
# CMP0091 OLD, which is this tree's cmake_minimum_required(3.5) unless a
# toolchain raises the policy. The platform module writes /MD into
# CMAKE_<LANG>_FLAGS_<CONFIG>, that flag is what cl sees, and
# MSVC_RUNTIME_LIBRARY is ignored. /MDd contains /MD, so the same
# replacement makes Debug /MTd.
#
# CMP0091 NEW. Those flag variables carry no runtime token. cl reads
# MSVC_RUNTIME_LIBRARY. Unset, the default is the dynamic DLL runtime.
# An explicit /MD left in the flags overrides the property, so the
# replacement still runs and a dynamic token that survives it stops
# configure.
#
# Debug is /MTd either way. That is the static triplet's debug libraries.
# Rust's +crt-static (rust/.cargo/config.toml) is libcmt in every profile,
# and cc passes /MT, so a Debug image still mixes libcmtd with libcmt.
# Release, RelWithDebInfo and MinSizeRel are /MT. The link check builds
# Release.
#
# A configuration with no runtime token, under the OLD spelling, would
# otherwise be cl's own default of /MD. The static token is appended
# there. Under the NEW spelling the property is the token, and appending
# a second one would put /MT beside Debug's /MTd.

if(NOT MSVC)
  return()
endif()

if(NOT STATIC)
  message(FATAL_ERROR
    "An MSVC build links the static C runtime: the Rust libraries are "
    "built with +crt-static (rust/.cargo/config.toml), and a non-static "
    "build would mix /MD C++ with them. Configure with -DSTATIC=ON "
    "(the MSVC default).")
endif()

set(_shekyl_crt_cmp0091 "")
if(POLICY CMP0091)
  cmake_policy(GET CMP0091 _shekyl_crt_cmp0091)
  if(DEFINED CMAKE_MSVC_RUNTIME_LIBRARY)
    # vcpkg's static triplet keeps the letters DLL inside a generator
    # expression that expands to nothing unless the linkage is dynamic:
    # $<$<STREQUAL:static,dynamic>:DLL>. Fold each STREQUAL expression,
    # then a remaining DLL is the dynamic runtime.
    set(_shekyl_crt_runtime "${CMAKE_MSVC_RUNTIME_LIBRARY}")
    while("${_shekyl_crt_runtime}" MATCHES "\\$<\\$<STREQUAL:([^,>]*),([^>]*)>:([^>]*)>")
      set(_shekyl_crt_left "${CMAKE_MATCH_1}")
      set(_shekyl_crt_right "${CMAKE_MATCH_2}")
      set(_shekyl_crt_branch "${CMAKE_MATCH_3}")
      if("${_shekyl_crt_left}" STREQUAL "${_shekyl_crt_right}")
        set(_shekyl_crt_replacement "${_shekyl_crt_branch}")
      else()
        set(_shekyl_crt_replacement "")
      endif()
      set(_shekyl_crt_genex "$<$<STREQUAL:${_shekyl_crt_left},${_shekyl_crt_right}>:${_shekyl_crt_branch}>")
      string(FIND "${_shekyl_crt_runtime}" "${_shekyl_crt_genex}" _shekyl_crt_genex_at)
      if(_shekyl_crt_genex_at LESS 0)
        message(FATAL_ERROR
          "CMAKE_MSVC_RUNTIME_LIBRARY is \"${CMAKE_MSVC_RUNTIME_LIBRARY}\" and its "
          "STREQUAL generator expression could not be folded.")
      endif()
      string(REPLACE "${_shekyl_crt_genex}" "${_shekyl_crt_replacement}"
        _shekyl_crt_runtime "${_shekyl_crt_runtime}")
    endwhile()
    if("${_shekyl_crt_runtime}" MATCHES "DLL")
      message(FATAL_ERROR
        "CMAKE_MSVC_RUNTIME_LIBRARY is \"${CMAKE_MSVC_RUNTIME_LIBRARY}\", which "
        "selects the dynamic C runtime. Shekyl's MSVC build uses the static "
        "runtime because the Rust libraries are built with +crt-static "
        "(rust/.cargo/config.toml). Leave the variable unset, or set it to "
        "MultiThreaded$<$<CONFIG:Debug>:Debug> (Debug is /MTd). "
        "x64-windows-static is the triplet that links that runtime.")
    endif()
    unset(_shekyl_crt_runtime)
    unset(_shekyl_crt_left)
    unset(_shekyl_crt_right)
    unset(_shekyl_crt_branch)
    unset(_shekyl_crt_replacement)
    unset(_shekyl_crt_genex)
    unset(_shekyl_crt_genex_at)
  else()
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
      CACHE STRING "Static MSVC C runtime. Debug selects MultiThreadedDebug (/MTd).")
  endif()
endif()

# CMake's four, plus any name the generator added. A single-config
# generator leaves CMAKE_CONFIGURATION_TYPES empty and still initializes
# the four flag variables, so the four are always rewritten.
set(SHEKYL_MSVC_CRT_CONFIGS DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
foreach(SHEKYL_MSVC_CRT_CONFIG IN LISTS CMAKE_CONFIGURATION_TYPES)
  string(TOUPPER "${SHEKYL_MSVC_CRT_CONFIG}" SHEKYL_MSVC_CRT_CONFIG)
  list(APPEND SHEKYL_MSVC_CRT_CONFIGS "${SHEKYL_MSVC_CRT_CONFIG}")
endforeach()
list(REMOVE_DUPLICATES SHEKYL_MSVC_CRT_CONFIGS)

foreach(SHEKYL_MSVC_CRT_CONFIG IN LISTS SHEKYL_MSVC_CRT_CONFIGS)
  foreach(SHEKYL_MSVC_CRT_LANG C CXX)
    set(_shekyl_crt_flags "CMAKE_${SHEKYL_MSVC_CRT_LANG}_FLAGS_${SHEKYL_MSVC_CRT_CONFIG}")
    string(REPLACE "/MD" "/MT" ${_shekyl_crt_flags} "${${_shekyl_crt_flags}}")
    if("${${_shekyl_crt_flags}}" MATCHES "(^| )[/-]MDd?($| )")
      message(FATAL_ERROR
        "${_shekyl_crt_flags} is \"${${_shekyl_crt_flags}}\" and still names the "
        "dynamic C runtime (/MD, /MDd, -MD, or -MDd).")
    endif()
    if(NOT "${_shekyl_crt_cmp0091}" STREQUAL "NEW")
      if(NOT "${${_shekyl_crt_flags}}" MATCHES "(^| )[/-]MTd?($| )")
        if("${SHEKYL_MSVC_CRT_CONFIG}" STREQUAL "DEBUG")
          string(APPEND ${_shekyl_crt_flags} " /MTd")
        else()
          string(APPEND ${_shekyl_crt_flags} " /MT")
        endif()
      endif()
      if(NOT "${${_shekyl_crt_flags}}" MATCHES "(^| )[/-]MTd?($| )")
        message(FATAL_ERROR
          "${_shekyl_crt_flags} is \"${${_shekyl_crt_flags}}\" and does not name "
          "the static C runtime. CMP0091 is not NEW, so this flag is what cl sees.")
      endif()
    endif()
  endforeach()
endforeach()

message(STATUS
  "MSVC static C runtime: CMP0091='${_shekyl_crt_cmp0091}' "
  "CMAKE_MSVC_RUNTIME_LIBRARY='${CMAKE_MSVC_RUNTIME_LIBRARY}' "
  "configs='${SHEKYL_MSVC_CRT_CONFIGS}'")

unset(_shekyl_crt_flags)
unset(_shekyl_crt_cmp0091)
unset(SHEKYL_MSVC_CRT_LANG)
unset(SHEKYL_MSVC_CRT_CONFIG)
unset(SHEKYL_MSVC_CRT_CONFIGS)
