# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Writes the GNU ld response file that makes a Rust binary's link extract,
# from the rlibs, every member defining a Rust export the C++ closure
# references. Run as a script by `shekyl_rust_link_cxx_closure`
# (cmake/BuildRust.cmake), which documents why it is needed:
#
#   cmake -D NM=<nm>[|<nm>…] -D ARCHIVES=<a.a>[|<b.a>…] -D PREFIX=shekyl_
#         -D OUT=<file> -P cmake/RustLinkUndefined.cmake
#
# NM is one or more nm tools, tried in order; the first that can read the
# archives is used (a cross build's host nm may not read the target's
# objects). ARCHIVES are the C++ closure's first-party static libraries.
# PREFIX is the prefix every C-visible Rust export carries
# (scripts/ci/check_ffi_signatures.sh). OUT receives one
# `--undefined=<symbol>` per line, for every `PREFIX*` symbol some member of
# ARCHIVES leaves undefined, and is rewritten only when its content
# changes, so an unchanged closure does not disturb the link. A closure
# that references no such symbol is an error, not an empty file (rule 47):
# the C++ side calling into Rust is the subject this file exists for.

foreach(_var IN ITEMS NM ARCHIVES PREFIX OUT)
    if(NOT DEFINED ${_var} OR "${${_var}}" STREQUAL "")
        message(FATAL_ERROR "RustLinkUndefined: -D ${_var}=… is required")
    endif()
endforeach()

string(REPLACE "|" ";" _nm_tools "${NM}")
string(REPLACE "|" ";" _archives "${ARCHIVES}")

set(_listing "")
set(_used "")
foreach(_nm IN LISTS _nm_tools)
    execute_process(
        COMMAND "${_nm}" --undefined-only ${_archives}
        RESULT_VARIABLE _rc
        OUTPUT_VARIABLE _listing
        ERROR_VARIABLE _err)
    if(_rc EQUAL 0)
        set(_used "${_nm}")
        break()
    endif()
    message(STATUS "RustLinkUndefined: ${_nm} could not read the closure (${_err}); trying the next")
endforeach()
if("${_used}" STREQUAL "")
    message(FATAL_ERROR "RustLinkUndefined: no nm tool could read the C++ closure (tried: ${NM})")
endif()

# nm's default (BSD) listing: whitespace, the type letter `U`, whitespace,
# the name. The optional `_` is the C symbol prefix of targets that have
# one (none of ours today; GNU ld wants the mangled name, so it is kept).
string(REGEX MATCHALL "[ \t]U[ \t]+_?${PREFIX}[A-Za-z0-9_]+" _hits "${_listing}")
set(_symbols "")
foreach(_hit IN LISTS _hits)
    string(REGEX REPLACE "^[ \t]U[ \t]+" "" _symbol "${_hit}")
    list(APPEND _symbols "${_symbol}")
endforeach()
list(SORT _symbols)
list(REMOVE_DUPLICATES _symbols)
list(LENGTH _symbols _count)
if(_count EQUAL 0)
    message(FATAL_ERROR
        "RustLinkUndefined: the C++ closure references no ${PREFIX}* symbol "
        "(${_used} over ${ARCHIVES}); the Rust/C++ boundary this file serves has vanished "
        "or the listing format changed")
endif()

set(_content "")
foreach(_symbol IN LISTS _symbols)
    string(APPEND _content "--undefined=${_symbol}\n")
endforeach()
file(WRITE "${OUT}.tmp" "${_content}")
execute_process(COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${OUT}.tmp" "${OUT}"
    RESULT_VARIABLE _rc)
file(REMOVE "${OUT}.tmp")
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "RustLinkUndefined: could not write ${OUT}")
endif()
message(STATUS "RustLinkUndefined: ${_count} ${PREFIX}* symbols forced for ${OUT}")
