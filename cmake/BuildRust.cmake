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
endif()

if(RUST_TARGET_TRIPLE)
    set(RUST_TARGET_FLAG "--target" "${RUST_TARGET_TRIPLE}")
    set(RUST_BUILD_DIR "${RUST_SOURCE_DIR}/target/${RUST_TARGET_TRIPLE}/${RUST_PROFILE}")
    message(STATUS "Rust cross-compile target: ${RUST_TARGET_TRIPLE}")

    # When cross-compiling for Windows with mingw, tell cargo which linker to use.
    if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        find_program(MINGW_LINKER x86_64-w64-mingw32-gcc)
        if(MINGW_LINKER)
            string(TOUPPER "${RUST_TARGET_TRIPLE}" _upper_triple)
            string(REPLACE "-" "_" _upper_triple "${_upper_triple}")
            set(RUST_CROSS_ENV "CARGO_TARGET_${_upper_triple}_LINKER=${MINGW_LINKER}")
        endif()
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

# Build the cargo command; use cmake -E env only when cross-compiling
if(RUST_CROSS_ENV)
    add_custom_command(
        OUTPUT ${SHEKYL_FFI_LIBRARY}
        COMMAND ${CMAKE_COMMAND} -E env "${RUST_CROSS_ENV}"
            ${CARGO_EXECUTABLE} build ${RUST_BUILD_FLAG} ${RUST_TARGET_FLAG}
        WORKING_DIRECTORY ${RUST_SOURCE_DIR}
        COMMENT "${_rust_comment}"
        VERBATIM
    )
else()
    add_custom_command(
        OUTPUT ${SHEKYL_FFI_LIBRARY}
        COMMAND ${CARGO_EXECUTABLE} build ${RUST_BUILD_FLAG} ${RUST_TARGET_FLAG}
        WORKING_DIRECTORY ${RUST_SOURCE_DIR}
        COMMENT "${_rust_comment}"
        VERBATIM
    )
endif()

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
