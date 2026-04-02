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
        set(RUST_TARGET_TRIPLE "x86_64-pc-windows-gnu")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i686|x86")
        set(RUST_TARGET_TRIPLE "i686-pc-windows-gnu")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64")
        set(RUST_TARGET_TRIPLE "aarch64-pc-windows-gnullvm")
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
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "armv7")
        set(RUST_TARGET_TRIPLE "armv7-linux-androideabi")
    endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
        set(RUST_TARGET_TRIPLE "x86_64-unknown-freebsd")
    endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_CROSSCOMPILING)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        set(RUST_TARGET_TRIPLE "aarch64-unknown-linux-gnu")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "armv7|arm")
        set(RUST_TARGET_TRIPLE "armv7-unknown-linux-gnueabihf")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
        set(RUST_TARGET_TRIPLE "x86_64-unknown-linux-gnu")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i686|i386")
        set(RUST_TARGET_TRIPLE "i686-unknown-linux-gnu")
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
        if(CMAKE_C_COMPILER)
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

if(RUST_TARGET_TRIPLE AND CMAKE_C_COMPILER)
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

# ── shekyl-ffi (crypto, staking, economics — linked by all targets) ──────────

add_custom_command(
    OUTPUT ${SHEKYL_FFI_LIBRARY}
    COMMAND ${CMAKE_COMMAND} -E env ${_rust_env_clear}
        ${CARGO_EXECUTABLE} build ${RUST_BUILD_FLAG} ${RUST_TARGET_FLAG}
        -p shekyl-ffi
    WORKING_DIRECTORY ${RUST_SOURCE_DIR}
    COMMENT "${_rust_comment} (shekyl-ffi)"
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
        ${CARGO_EXECUTABLE} build ${RUST_BUILD_FLAG} ${RUST_TARGET_FLAG}
        -p shekyl-daemon-rpc --lib
    WORKING_DIRECTORY ${RUST_SOURCE_DIR}
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
