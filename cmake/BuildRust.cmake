# BuildRust.cmake -- Integrate Cargo workspace into CMake build
#
# Adds a custom target that builds the Rust workspace under rust/ and
# produces a static library (libshekyl_ffi.a) that C++ targets can link against.

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
    set(RUST_BUILD_DIR "${RUST_SOURCE_DIR}/target/release")
else()
    set(RUST_BUILD_FLAG "")
    set(RUST_BUILD_DIR "${RUST_SOURCE_DIR}/target/debug")
endif()

set(SHEKYL_FFI_LIBRARY "${RUST_BUILD_DIR}/libshekyl_ffi.a")

add_custom_command(
    OUTPUT ${SHEKYL_FFI_LIBRARY}
    COMMAND ${CARGO_EXECUTABLE} build ${RUST_BUILD_FLAG}
    WORKING_DIRECTORY ${RUST_SOURCE_DIR}
    COMMENT "Building Shekyl Rust workspace"
    VERBATIM
)

add_custom_target(shekyl_rust ALL DEPENDS ${SHEKYL_FFI_LIBRARY})

add_library(shekyl_ffi STATIC IMPORTED GLOBAL)
set_target_properties(shekyl_ffi PROPERTIES
    IMPORTED_LOCATION ${SHEKYL_FFI_LIBRARY}
)
add_dependencies(shekyl_ffi shekyl_rust)

# Rust static libraries on Linux need to link against pthread and dl
if(UNIX AND NOT APPLE)
    set(SHEKYL_FFI_LINK_LIBS "shekyl_ffi;pthread;dl" CACHE INTERNAL "Rust FFI linker flags for C++ targets" FORCE)
elseif(APPLE)
    set(SHEKYL_FFI_LINK_LIBS "shekyl_ffi;-framework Security;-framework CoreFoundation" CACHE INTERNAL "Rust FFI linker flags for C++ targets" FORCE)
else()
    set(SHEKYL_FFI_LINK_LIBS "shekyl_ffi;ws2_32;userenv;bcrypt" CACHE INTERNAL "Rust FFI linker flags for C++ targets" FORCE)
endif()
