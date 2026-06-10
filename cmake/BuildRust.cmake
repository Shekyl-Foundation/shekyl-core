# Copyright (c) 2025-2026, The Shekyl Foundation
# BuildRust.cmake -- Integrate Cargo workspace into CMake build
#
# Adds a custom target that builds the Rust workspace under rust/ and
# produces a static library (libshekyl_ffi.a) that C++ targets can link against.
# Supports native builds and cross-compilation (detected via CMAKE_SYSTEM_NAME).

find_program(CARGO_EXECUTABLE cargo HINTS "$ENV{HOME}/.cargo/bin")

if(NOT CARGO_EXECUTABLE)
    message(STATUS "Cargo not found -- Rust modules will not be built")
    set(SHEKYL_RUST_ENABLED OFF CACHE INTERNAL "Whether Rust workspace build is enabled" FORCE)
    set(SHEKYL_FFI_LINK_LIBS "" CACHE INTERNAL "Rust FFI linker flags for C++ targets" FORCE)
    return()
endif()

message(STATUS "Found cargo: ${CARGO_EXECUTABLE}")
set(SHEKYL_RUST_ENABLED ON CACHE INTERNAL "Whether Rust workspace build is enabled" FORCE)

set(RUST_SOURCE_DIR "${CMAKE_SOURCE_DIR}/rust")

if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    set(RUST_BUILD_FLAG "--release")
    set(RUST_PROFILE "release")
else()
    set(RUST_BUILD_FLAG "")
    set(RUST_PROFILE "debug")
endif()

# Map CMAKE_SYSTEM_NAME + CMAKE_SYSTEM_PROCESSOR to a Rust target triple.
# When cross-compiling (e.g. via contrib/depends), CMAKE_SYSTEM_NAME differs
# from the host OS.
set(RUST_TARGET_FLAG "")
set(RUST_TARGET_TRIPLE "")
set(RUST_CROSS_ENV "")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
        if(MSVC)
            set(RUST_TARGET_TRIPLE "x86_64-pc-windows-msvc")
        else()
            set(RUST_TARGET_TRIPLE "x86_64-pc-windows-gnu")
        endif()
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64")
        if(MSVC)
            set(RUST_TARGET_TRIPLE "aarch64-pc-windows-msvc")
        else()
            set(RUST_TARGET_TRIPLE "aarch64-pc-windows-gnullvm")
        endif()
    endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        set(RUST_TARGET_TRIPLE "aarch64-apple-darwin")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
        set(RUST_TARGET_TRIPLE "x86_64-apple-darwin")
    endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "Android")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        set(RUST_TARGET_TRIPLE "aarch64-linux-android")
    endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
        set(RUST_TARGET_TRIPLE "x86_64-unknown-freebsd")
    endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_CROSSCOMPILING)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        set(RUST_TARGET_TRIPLE "aarch64-unknown-linux-gnu")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
        set(RUST_TARGET_TRIPLE "x86_64-unknown-linux-gnu")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "riscv64")
        set(RUST_TARGET_TRIPLE "riscv64gc-unknown-linux-gnu")
    endif()
endif()

if(RUST_TARGET_TRIPLE)
    set(RUST_TARGET_FLAG "--target" "${RUST_TARGET_TRIPLE}")
    set(RUST_BUILD_DIR "${RUST_SOURCE_DIR}/target/${RUST_TARGET_TRIPLE}/${RUST_PROFILE}")
    message(STATUS "Rust cross-compile target: ${RUST_TARGET_TRIPLE}")

    # Tell cargo which linker to use for cross-compilation targets.
    string(TOUPPER "${RUST_TARGET_TRIPLE}" _upper_triple)
    string(REPLACE "-" "_" _upper_triple "${_upper_triple}")

    if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        if(MSVC)
            # Let rustc select the MSVC linker toolchain. This keeps the GNU
            # linker override path isolated to MinGW builds.
            set(RUST_CROSS_ENV "")
        elseif(CMAKE_C_COMPILER)
            set(RUST_CROSS_ENV "CARGO_TARGET_${_upper_triple}_LINKER=${CMAKE_C_COMPILER}")
        else()
            find_program(MINGW_LINKER x86_64-w64-mingw32-gcc)
            if(MINGW_LINKER)
                set(RUST_CROSS_ENV "CARGO_TARGET_${_upper_triple}_LINKER=${MINGW_LINKER}")
            endif()
        endif()
    elseif(CMAKE_C_COMPILER)
        set(RUST_CROSS_ENV "CARGO_TARGET_${_upper_triple}_LINKER=${CMAKE_C_COMPILER}")
    endif()
else()
    set(RUST_BUILD_DIR "${RUST_SOURCE_DIR}/target/${RUST_PROFILE}")
endif()

# Determine library name: .a on Unix, .lib on MSVC, .a with mingw
if(CMAKE_SYSTEM_NAME STREQUAL "Windows" AND NOT MSVC)
    set(SHEKYL_FFI_LIBRARY "${RUST_BUILD_DIR}/libshekyl_ffi.a")
elseif(MSVC)
    set(SHEKYL_FFI_LIBRARY "${RUST_BUILD_DIR}/shekyl_ffi.lib")
else()
    set(SHEKYL_FFI_LIBRARY "${RUST_BUILD_DIR}/libshekyl_ffi.a")
endif()

# Build the comment string
if(RUST_TARGET_TRIPLE)
    set(_rust_comment "Building Shekyl Rust workspace for ${RUST_TARGET_TRIPLE}")
else()
    set(_rust_comment "Building Shekyl Rust workspace")
endif()

# Build the cargo command.
# Clear generic CC/CXX/CFLAGS/CXXFLAGS/LDFLAGS so that Rust's build-script
# and proc-macro compilation targets the build host, not the cross target.
# Then set per-target CC_<TRIPLE>/AR_<TRIPLE>/CFLAGS_<TRIPLE> so crates that
# compile C code for the target (e.g. ring) can locate the cross-compiler.
set(_rust_env_clear
    "CC=" "CXX=" "CFLAGS=" "CXXFLAGS=" "LDFLAGS="
    "AR=" "RANLIB=" "NM="
)

if(RUST_CROSS_ENV)
    list(APPEND _rust_env_clear "${RUST_CROSS_ENV}")
endif()

if(RUST_TARGET_TRIPLE AND CMAKE_C_COMPILER AND NOT MSVC)
    string(REPLACE "-" "_" _cc_triple "${RUST_TARGET_TRIPLE}")

    set(_rust_cc "${CMAKE_C_COMPILER}")
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND NOT CMAKE_CROSSCOMPILING)
        find_program(_system_clang clang)
        if(_system_clang)
            set(_rust_cc "${_system_clang}")
        endif()
    endif()

    list(APPEND _rust_env_clear "CC_${_cc_triple}=${_rust_cc}")
    if(CMAKE_AR)
        list(APPEND _rust_env_clear "AR_${_cc_triple}=${CMAKE_AR}")
    endif()
    string(STRIP "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_INIT}" _target_cflags)
    if(CMAKE_C_COMPILER_TARGET)
        string(STRIP "${_target_cflags} --target=${CMAKE_C_COMPILER_TARGET}" _target_cflags)
    endif()
    if(CMAKE_OSX_SYSROOT)
        string(STRIP "${_target_cflags} --sysroot=${CMAKE_OSX_SYSROOT}" _target_cflags)
    endif()
    if(_target_cflags)
        list(APPEND _rust_env_clear "CFLAGS_${_cc_triple}=${_target_cflags}")
    endif()
    # Clang 9 (depends cross-compiler) does not recognise macOS version 11.0+.
    # Apple aliases 10.16 == 11.0; cc-rs respects MACOSX_DEPLOYMENT_TARGET.
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND CMAKE_CROSSCOMPILING)
        list(APPEND _rust_env_clear "MACOSX_DEPLOYMENT_TARGET=10.16")
    endif()
endif()

# For native Darwin builds, align ring/cc-rs deployment target with CMake's
# so that object files don't trigger "built for newer macOS" linker warnings.
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND NOT CMAKE_CROSSCOMPILING)
    if(CMAKE_OSX_DEPLOYMENT_TARGET)
        list(APPEND _rust_env_clear "MACOSX_DEPLOYMENT_TARGET=${CMAKE_OSX_DEPLOYMENT_TARGET}")
    else()
        list(APPEND _rust_env_clear "MACOSX_DEPLOYMENT_TARGET=10.15")
    endif()
endif()

# ── Source-change tracking for the cargo custom commands ─────────────────────
#
# Each cargo invocation below is wrapped in an `add_custom_command(OUTPUT …)`.
# Without an explicit `DEPENDS` list, the generator (Ninja/Make) treats the
# output `.a` as up-to-date for as long as the file exists on disk — it never
# re-invokes cargo when a source under `rust/` changes. The result is a silently
# stale archive: the C++ side relinks against a `libshekyl_*.a` that predates
# the current Rust sources, which is exactly the failure that linked a month-old
# FFI into the daemon.
#
# The dependency set below tracks the inputs that live under `rust/`: every
# `.rs`, every `Cargo.toml`, the lockfile, and `.md` files (which feed the build
# via `#![doc = include_str!("../README.md")]`). It is deliberately *not* a
# complete model of cargo's inputs — `include_str!` / `include_bytes!` targets
# that live outside `rust/` (e.g. test vectors under `docs/`, `config/*.json`)
# are not tracked here. Those are test/doc inputs that affect test binaries and
# rustdoc, not the linked production archives this file builds (shekyl-ffi,
# shekyl-logging, shekyl-daemon-rpc), whose `include_*!` uses are confined to
# `#[cfg(test)]`. A tracked change still triggers a cargo run, and cargo's own
# fingerprinting then re-checks the full input set and decides whether to
# rewrite each archive (so a no-op change does not force a C++ relink).
#
# `CONFIGURE_DEPENDS` makes the generator re-glob at build time, so newly added
# source files are picked up without a manual re-configure. The `/target/`
# filter keeps cargo's own build artifacts out of the dependency set.
file(GLOB_RECURSE _shekyl_rust_sources CONFIGURE_DEPENDS
    "${RUST_SOURCE_DIR}/*.rs"
    "${RUST_SOURCE_DIR}/*.md"
)
list(FILTER _shekyl_rust_sources EXCLUDE REGEX "/target/")
file(GLOB_RECURSE _shekyl_rust_manifests CONFIGURE_DEPENDS "${RUST_SOURCE_DIR}/*Cargo.toml")
list(FILTER _shekyl_rust_manifests EXCLUDE REGEX "/target/")
set(_shekyl_rust_deps
    ${_shekyl_rust_sources}
    ${_shekyl_rust_manifests}
    "${RUST_SOURCE_DIR}/Cargo.lock"
)

# ── shekyl-ffi (crypto, staking, economics — linked by all targets) ──────────

add_custom_command(
    OUTPUT ${SHEKYL_FFI_LIBRARY}
    COMMAND ${CMAKE_COMMAND} -E env ${_rust_env_clear}
        ${CARGO_EXECUTABLE} build --locked ${RUST_BUILD_FLAG} ${RUST_TARGET_FLAG}
        -p shekyl-ffi
    WORKING_DIRECTORY ${RUST_SOURCE_DIR}
    DEPENDS ${_shekyl_rust_deps}
    COMMENT "${_rust_comment} (shekyl-ffi + shekyl-fcmp)"
    VERBATIM
)

add_custom_target(shekyl_rust ALL DEPENDS ${SHEKYL_FFI_LIBRARY})

add_library(shekyl_ffi STATIC IMPORTED GLOBAL)
set_target_properties(shekyl_ffi PROPERTIES
    IMPORTED_LOCATION ${SHEKYL_FFI_LIBRARY}
)
add_dependencies(shekyl_ffi shekyl_rust)

if(UNIX AND NOT APPLE)
    set(SHEKYL_FFI_LINK_LIBS "shekyl_ffi;pthread;dl" CACHE INTERNAL "Rust FFI linker flags for C++ targets" FORCE)
elseif(APPLE)
    set(SHEKYL_FFI_LINK_LIBS "shekyl_ffi;-framework Security;-framework CoreFoundation" CACHE INTERNAL "Rust FFI linker flags for C++ targets" FORCE)
else()
    set(SHEKYL_FFI_LINK_LIBS "shekyl_ffi;ws2_32;userenv;bcrypt;ntdll" CACHE INTERNAL "Rust FFI linker flags for C++ targets" FORCE)
endif()

# ── shekyl-logging (tracing subscriber + C ABI for misc_log_ex.h) ───────────
#
# Built from the same workspace as shekyl-ffi, just via `-p shekyl-logging`,
# so this reuses the same target-triple / cross-env setup resolved above.
# Every C++ target that includes `src/shekyl/shekyl_log.h` (i.e. every TU
# that transitively pulls in `contrib/epee/include/misc_log_ex.h`) links
# against `libshekyl_logging.a` (Cargo's default `lib<crate_name>.a`
# naming for the `shekyl-logging` crate) — which is effectively the
# whole project once the easylogging++ shim is retired. We expose it
# as the CMake IMPORTED target `shekyl_log` (short name, matches the
# header it mirrors) and append that target to `SHEKYL_FFI_LINK_LIBS`
# so existing consumers pick it up transparently;
# duplicate Rust-runtime symbols across the two archives are resolved by
# rustc's weak-symbol emission (same pattern that already lets
# `shekyl_daemon_rpc` coexist with `shekyl_ffi` in the daemon binary).

if(CMAKE_SYSTEM_NAME STREQUAL "Windows" AND NOT MSVC)
    set(SHEKYL_LOG_LIBRARY "${RUST_BUILD_DIR}/libshekyl_logging.a")
elseif(MSVC)
    set(SHEKYL_LOG_LIBRARY "${RUST_BUILD_DIR}/shekyl_logging.lib")
else()
    set(SHEKYL_LOG_LIBRARY "${RUST_BUILD_DIR}/libshekyl_logging.a")
endif()

add_custom_command(
    OUTPUT ${SHEKYL_LOG_LIBRARY}
    COMMAND ${CMAKE_COMMAND} -E env ${_rust_env_clear}
        ${CARGO_EXECUTABLE} build --locked ${RUST_BUILD_FLAG} ${RUST_TARGET_FLAG}
        -p shekyl-logging
    WORKING_DIRECTORY ${RUST_SOURCE_DIR}
    DEPENDS ${_shekyl_rust_deps}
    COMMENT "${_rust_comment} (shekyl-logging)"
    VERBATIM
)

add_custom_target(shekyl_log_rust ALL DEPENDS ${SHEKYL_LOG_LIBRARY})

add_library(shekyl_log STATIC IMPORTED GLOBAL)
set_target_properties(shekyl_log PROPERTIES
    IMPORTED_LOCATION ${SHEKYL_LOG_LIBRARY}
)
add_dependencies(shekyl_log shekyl_log_rust)

# Fold shekyl_log into the shared FFI link set so every C++ target that
# pulls in SHEKYL_FFI_LINK_LIBS automatically resolves the new log FFI
# symbols. Keeping the platform-specific system-library tail (pthread/dl,
# Security/CoreFoundation, ws2_32/userenv/bcrypt/ntdll) at the end of the
# list preserves the left-to-right link-order semantics that GNU ld cares
# about for static archives.
if(UNIX AND NOT APPLE)
    set(SHEKYL_FFI_LINK_LIBS "shekyl_ffi;shekyl_log;pthread;dl" CACHE INTERNAL "Rust FFI linker flags for C++ targets" FORCE)
elseif(APPLE)
    set(SHEKYL_FFI_LINK_LIBS "shekyl_ffi;shekyl_log;-framework Security;-framework CoreFoundation" CACHE INTERNAL "Rust FFI linker flags for C++ targets" FORCE)
else()
    set(SHEKYL_FFI_LINK_LIBS "shekyl_ffi;shekyl_log;ws2_32;userenv;bcrypt;ntdll" CACHE INTERNAL "Rust FFI linker flags for C++ targets" FORCE)
endif()

# ── shekyl-daemon-rpc (Axum server — linked only by the daemon target) ──────

if(CMAKE_SYSTEM_NAME STREQUAL "Windows" AND NOT MSVC)
    set(SHEKYL_DAEMON_RPC_LIBRARY "${RUST_BUILD_DIR}/libshekyl_daemon_rpc.a")
elseif(MSVC)
    set(SHEKYL_DAEMON_RPC_LIBRARY "${RUST_BUILD_DIR}/shekyl_daemon_rpc.lib")
else()
    set(SHEKYL_DAEMON_RPC_LIBRARY "${RUST_BUILD_DIR}/libshekyl_daemon_rpc.a")
endif()

add_custom_command(
    OUTPUT ${SHEKYL_DAEMON_RPC_LIBRARY}
    COMMAND ${CMAKE_COMMAND} -E env ${_rust_env_clear}
        ${CARGO_EXECUTABLE} build --locked ${RUST_BUILD_FLAG} ${RUST_TARGET_FLAG}
        -p shekyl-daemon-rpc --lib
    WORKING_DIRECTORY ${RUST_SOURCE_DIR}
    DEPENDS ${_shekyl_rust_deps}
    COMMENT "${_rust_comment} (shekyl-daemon-rpc)"
    VERBATIM
)

add_custom_target(shekyl_daemon_rpc_rust ALL DEPENDS ${SHEKYL_DAEMON_RPC_LIBRARY})

add_library(shekyl_daemon_rpc STATIC IMPORTED GLOBAL)
set_target_properties(shekyl_daemon_rpc PROPERTIES
    IMPORTED_LOCATION ${SHEKYL_DAEMON_RPC_LIBRARY}
)
add_dependencies(shekyl_daemon_rpc shekyl_daemon_rpc_rust)

if(UNIX AND NOT APPLE)
    set(SHEKYL_DAEMON_RPC_LINK_LIBS "shekyl_daemon_rpc;pthread;dl" CACHE INTERNAL "Rust daemon RPC linker flags (daemon only)" FORCE)
elseif(APPLE)
    set(SHEKYL_DAEMON_RPC_LINK_LIBS "shekyl_daemon_rpc;-framework Security;-framework CoreFoundation" CACHE INTERNAL "Rust daemon RPC linker flags (daemon only)" FORCE)
else()
    set(SHEKYL_DAEMON_RPC_LINK_LIBS "shekyl_daemon_rpc;ws2_32;userenv;bcrypt;ntdll" CACHE INTERNAL "Rust daemon RPC linker flags (daemon only)" FORCE)
endif()

# ── Single-Rust-image contract for the daemon ────────────────────────────────
#
# `shekyl-daemon-rpc` depends on the `shekyl-logging` crate, so
# `libshekyl_daemon_rpc.a` carries the `shekyl_log_*` C exports *and* the
# one `tracing-core` `GLOBAL_DISPATCH` its `tracing::*` macros dispatch
# through. The daemon must resolve every `shekyl_log_*` reference from
# that archive — never from the standalone `libshekyl_logging.a` that
# `SHEKYL_FFI_LINK_LIBS` drags in transitively (epee/cryptonote_basic/
# cryptonote_core all link it) — otherwise the binary ends up with two
# dispatcher copies and daemon-rpc's events are silently dropped
# (V3_WALLET_DECISION_LOG.md 2026-06-10 single-image amendment).
#
# Plain archive ordering cannot guarantee this: GNU ld pulls a member
# only when it defines a currently-undefined symbol, so an early
# daemon-rpc archive position would satisfy whichever `shekyl_log_*`
# refs exist at that point and leave the rest (e.g. mlog.o's init refs,
# which only appear when libepee.a is reached later) to resolve from the
# trailing standalone logging archive — a split-image mix. Force-loading
# the daemon-rpc archive defines the full `shekyl_log_*` surface from
# one image up front; the standalone archive then contributes nothing.
# The post-link nm gate on the daemon target asserts the result (exactly
# one GLOBAL_DISPATCH definition).
if(MSVC)
    set(SHEKYL_DAEMON_RPC_WHOLE_ARCHIVE "/WHOLEARCHIVE:${SHEKYL_DAEMON_RPC_LIBRARY}" CACHE INTERNAL "Force-load flags for libshekyl_daemon_rpc (daemon only)" FORCE)
elseif(APPLE)
    set(SHEKYL_DAEMON_RPC_WHOLE_ARCHIVE "-Wl,-force_load,${SHEKYL_DAEMON_RPC_LIBRARY}" CACHE INTERNAL "Force-load flags for libshekyl_daemon_rpc (daemon only)" FORCE)
else()
    set(SHEKYL_DAEMON_RPC_WHOLE_ARCHIVE "-Wl,--whole-archive;${SHEKYL_DAEMON_RPC_LIBRARY};-Wl,--no-whole-archive" CACHE INTERNAL "Force-load flags for libshekyl_daemon_rpc (daemon only)" FORCE)
endif()
