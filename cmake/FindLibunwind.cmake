# - Try to find libunwind
# Once done this will define
#
#  LIBUNWIND_FOUND - system has libunwind
#  LIBUNWIND_INCLUDE_DIR - the libunwind include directory
#  LIBUNWIND_LIBRARIES - Link these to use libunwind
#  LIBUNWIND_DEFINITIONS - Compiler switches required for using libunwind

# Copyright (c) 2006, Alexander Dymo, <adymo@kdevelop.org>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.

find_path(LIBUNWIND_INCLUDE_DIR libunwind.h
  /usr/include
  /usr/local/include
)

find_library(LIBUNWIND_LIBRARIES NAMES unwind )
# Do *not* prepend `-lgcc_eh` here. That was a legacy Monero carry-over
# from the era when some libstdc++ builds didn't pull in `libgcc_s`
# transitively and the C++ exception unwinder genuinely needed the
# static `libgcc_eh.a` symbols. On modern GCC + glibc the static
# archive is actively harmful: it bakes an *unversioned* copy of the
# `_Unwind_*` API (`_Unwind_RaiseException_Phase2`,
# `_Unwind_GetLanguageSpecificData`, ...) into the main executable,
# where it interleaves catastrophically with the versioned
# (`@@GCC_3.0`) copies in `libgcc_s.so.1` *and* with the namespaced
# (`__libunwind_*`) copies in `libunwind.so.8`. The observed failure
# mode on Debian 13 / Ubuntu 24.04 with `libunwind-dev` installed is
# that a `throw` propagates into `__gxx_personality_v0` (libstdc++),
# which resolves `_Unwind_GetLanguageSpecificData` by global symbol
# interposition to libunwind's wrapper, which then dereferences an
# `_Unwind_Context*` whose layout was built by libgcc_eh's
# `Phase2` — and SIGSEGVs inside libunwind. Observable in CI as
# `unit_tests (Subprocess aborted)` immediately after any exception
# that hits the `__cxa_throw` hook. Letting libstdc++ pull in
# `libgcc_s` on its own keeps the unwinder provider singular and
# version-matched.
#
# If a future target genuinely needs the static archive (embedded /
# fully-static / pre-C++11 toolchain), re-add it *per target* behind
# an explicit option; don't restore the global default.

# some versions of libunwind need liblzma, and we don't use pkg-config
# so we just look whether liblzma is installed, and add it if it is.
# It might not be actually needed, but doesn't hurt if it is not.
# We don't need any headers, just the lib, as it's privately needed.
message(STATUS "looking for liblzma")
find_library(LIBLZMA_LIBRARIES lzma )
if(NOT LIBLZMA_LIBRARIES STREQUAL "LIBLZMA_LIBRARIES-NOTFOUND")
  message(STATUS "liblzma found")
  set(LIBUNWIND_LIBRARIES "${LIBUNWIND_LIBRARIES};${LIBLZMA_LIBRARIES}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libunwind "Could not find libunwind" LIBUNWIND_INCLUDE_DIR LIBUNWIND_LIBRARIES)
# show the LIBUNWIND_INCLUDE_DIR and LIBUNWIND_LIBRARIES variables only in the advanced view
mark_as_advanced(LIBUNWIND_INCLUDE_DIR LIBUNWIND_LIBRARIES )

