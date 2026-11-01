# Copyright (c) 2025-2026, The Shekyl Foundation
# BuildRust.cmake -- Integrate Cargo workspace into CMake build
#
# Three cargo products: the static library `libshekyl_ffi.a` that the C++
# wallet-side targets and the unit tests link; the wallet binaries
# `shekyl-cli` and `shekyl-wallet-rpc`; and the daemon `shekyld`, a Rust
# binary whose link pulls in the C++ remnant's archives through Corrosion
# (DAEMON_CONFIG_CUTOVER.md DC-Q19, DC-Q23). Supports native builds and
# cross-compilation (detected via CMAKE_SYSTEM_NAME).

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
    # The library this file links is ${RUST_BUILD_DIR}/libshekyl_ffi.a, under
    # the workspace's own target directory. cargo builds wherever
    # CARGO_TARGET_DIR points, so a shell that exports it for Rust work would
    # otherwise build the fresh library elsewhere while the link step picks up
    # whatever stale copy sits at the linked path: a daemon with new C++ over
    # old Rust, and nothing to say so. The variable is pinned here to the
    # path the link reads.
    "CARGO_TARGET_DIR=${RUST_SOURCE_DIR}/target"
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

    # The same flags, forwarded to rustc's OWN link step.
    #
    # `CFLAGS_<triple>` above reaches cc-rs — the C compiled *inside* crates
    # like ring. It does not reach the link that produces a Rust executable,
    # which rustc drives itself by invoking `CARGO_TARGET_<TRIPLE>_LINKER`
    # with only the flags it generates. That gap was invisible while this
    # file built staticlibs only: an archive is `ar`, never a link. The
    # moment it also built binaries, the depends darwin cross failed twice
    # over — without `-B<prefix>` clang falls back to the host GNU ld, which
    # rejects Mach-O's `-dead_strip`, and without `--sysroot` rustc shells
    # out to `xcrun`, which does not exist in the cross container.
    #
    # Derived from the toolchain's own flags rather than hand-written per
    # platform: whatever CMake decided the target needs is what rustc links
    # with, so a new cross target inherits this for free instead of
    # rediscovering the same failure.
    if(CMAKE_CROSSCOMPILING AND _upper_triple)
        set(_rust_link_args "")
        if(_target_cflags)
            separate_arguments(_target_cflag_list NATIVE_COMMAND "${_target_cflags}")
            foreach(_flag IN LISTS _target_cflag_list)
                string(APPEND _rust_link_args " -C link-arg=${_flag}")
            endforeach()
        endif()

        # Same clang-9 version-spelling problem as MACOSX_DEPLOYMENT_TARGET
        # above, one layer down. On the link line rustc emits
        # `-mmacosx-version-min=11.0.0`, which the depends clang rejects
        # outright ("invalid version number"). The environment variable
        # cannot fix this one: rustc floors `aarch64-apple-darwin` at 11.0
        # because no arm64 Mac predates it, so it emits 11.0.0 whatever
        # MACOSX_DEPLOYMENT_TARGET says. Apple's own alias for that release
        # is 10.16 — the spelling this file already relies on — and clang
        # honours the last `-mmacosx-version-min` it is given, so appending
        # it after the forwarded flags is what takes effect.
        #
        # Deliberately aarch64-only: forcing 10.16 on x86_64 would raise
        # that binary's floor from the 10.15 the C++ side ships to 11.0,
        # dropping macOS versions still supported elsewhere in the build.
        # On arm64 it costs nothing, 11.0 being the floor already.
        if(RUST_TARGET_TRIPLE STREQUAL "aarch64-apple-darwin")
            string(APPEND _rust_link_args " -C link-arg=-mmacosx-version-min=10.16")
        endif()

        string(STRIP "${_rust_link_args}" _rust_link_args)
        if(_rust_link_args)
            list(APPEND _rust_env_clear
                "CARGO_TARGET_${_upper_triple}_RUSTFLAGS=${_rust_link_args}")
        endif()
    endif()

    # rustc consults SDKROOT before falling back to `xcrun` for the Apple
    # SDK path; the depends SDK is already named by CMAKE_OSX_SYSROOT.
    if(CMAKE_OSX_SYSROOT AND CMAKE_CROSSCOMPILING)
        list(APPEND _rust_env_clear "SDKROOT=${CMAKE_OSX_SYSROOT}")
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
# Each static-library cargo invocation below is wrapped in an
# `add_custom_command(OUTPUT …)`. The wallet binaries are a custom
# target that runs on every build: their release string is an
# environment variable, and an OUTPUT rule skips cargo when the binary
# is newer than its sources.
#
# Without an explicit `DEPENDS` list on a static library, the generator
# (Ninja/Make) treats the output `.a` as up-to-date for as long as the
# file exists on disk — it never re-invokes cargo when a source under
# `rust/` changes. The result is a silently stale archive: the C++ side
# relinks against a `libshekyl_*.a` that predates the current Rust
# sources, which is exactly the failure that linked a month-old FFI into
# the daemon.
#
# The dependency set below tracks the inputs that live under `rust/`: every
# `.rs`, every `Cargo.toml`, the lockfile, `.md` files (which feed the build
# via `#![doc = include_str!("../README.md")]`), and `.cargo/config.toml`.
# The globs do not see a dot-directory, so the cargo config is named
# explicitly. It is the +crt-static flag for the MSVC targets; cargo
# fingerprints it only once cargo runs, and this list is what makes CMake
# run cargo. Without it an incremental build keeps archives linked to the
# dynamic CRT.
#
# The set is deliberately *not* a complete model of cargo's inputs —
# `include_str!` / `include_bytes!` targets that live outside `rust/`
# (e.g. test vectors under `docs/`, `config/*.json`) are not tracked here.
# Those are test/doc inputs that affect test binaries and rustdoc, not the
# linked production archive this file builds (shekyl-ffi), whose
# `include_*!` uses are confined to `#[cfg(test)]`. A tracked change still
# triggers a cargo run, and cargo's own fingerprinting then re-checks the
# full input set and decides whether to rewrite the archive (so a no-op
# change does not force a C++ relink). The daemon binary is not in this
# list's reach: Corrosion's build target runs cargo on every build and
# cargo's fingerprint decides.
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
    "${RUST_SOURCE_DIR}/.cargo/config.toml"
)

# ── shekyl-ffi (crypto, staking, economics, logging — the wallet-side image) ─
#
# `shekyl-ffi` folds in the `shekyl-logging` crate (see its Cargo.toml), so
# `libshekyl_ffi.a` carries the full `shekyl_log_*` C ABI consumed by
# `contrib/epee/include/misc_log_ex.h` alongside the crypto/wallet FFI — one
# Rust image, one `tracing-core` GLOBAL_DISPATCH, per the single-image
# contract (V3_WALLET_DECISION_LOG.md). There is no standalone
# `libshekyl_logging.a` in the link anywhere; a second archive would carry a
# second dispatcher and silently drop the other image's tracing events.

add_custom_command(
    OUTPUT ${SHEKYL_FFI_LIBRARY}
    COMMAND ${CMAKE_COMMAND} -E env ${_rust_env_clear}
        ${CARGO_EXECUTABLE} build --locked ${RUST_BUILD_FLAG} ${RUST_TARGET_FLAG}
        -p shekyl-ffi
    WORKING_DIRECTORY ${RUST_SOURCE_DIR}
    DEPENDS ${_shekyl_rust_deps}
    COMMENT "${_rust_comment} (shekyl-ffi + shekyl-fcmp + shekyl-logging)"
    VERBATIM
)

add_custom_target(shekyl_rust ALL DEPENDS ${SHEKYL_FFI_LIBRARY})

add_library(shekyl_ffi STATIC IMPORTED GLOBAL)
set_target_properties(shekyl_ffi PROPERTIES
    IMPORTED_LOCATION ${SHEKYL_FFI_LIBRARY}
)
add_dependencies(shekyl_ffi shekyl_rust)

# ── The Rust archive's platform tail, for every C++ consumer ─────────────────
#
# `SHEKYL_FFI_LINK_LIBS` propagates transitively through the static
# libraries (cryptonote_basic / cryptonote_core list it), so every C++
# binary that links them gets the one Rust archive plus the system
# libraries its code needs. The daemon is no longer one of those binaries:
# `shekyld` is a Rust binary (below) whose link already carries the same
# crates as rlibs, and the closure walk that hands it the C++ archives
# drops `shekyl_ffi` from the list. A second copy of those symbols beside
# the rlibs would be the split tracing dispatcher the post-link nm gate in
# src/daemon/CMakeLists.txt exists to refuse.
#
# The platform tail stays at the end of the list to preserve the
# left-to-right link-order semantics GNU ld applies to static archives.
if(UNIX AND NOT APPLE)
    # `m` (libm): the Rust archive contains `f64` math the compiler lowers to
    # libm calls (e.g. `log10` in shekyl-relay-privacy, reachable from the
    # relay FFI exports' link closure). C++ binaries usually inherit libm
    # through libstdc++, but plain-C consumers (tests/crypto) do not — the
    # dependency belongs here, on the archive that owns it, not on each
    # consumer's link line.
    set(SHEKYL_FFI_LINK_LIBS "shekyl_ffi;m;pthread;dl" CACHE INTERNAL "Rust FFI linker flags for C++ targets" FORCE)
elseif(APPLE)
    set(SHEKYL_FFI_LINK_LIBS "shekyl_ffi;-framework Security;-framework CoreFoundation" CACHE INTERNAL "Rust FFI linker flags for C++ targets" FORCE)
else()
    set(SHEKYL_FFI_LINK_LIBS "shekyl_ffi;ws2_32;userenv;bcrypt;ntdll" CACHE INTERNAL "Rust FFI linker flags for C++ targets" FORCE)
endif()

# ── shekyld: a Rust binary (DC-Q19), linked through Corrosion (DC-Q23) ───────
#
# The daemon's process entry is Rust's `main` (rust/shekyld/src/main.rs);
# the C++ that remains — the console, the RPC command executor, and
# `Daemon` behind `shekyl_remnant_run` / `shekyl_remnant_stop` — is the
# static library `shekyld_remnant` (src/daemon/CMakeLists.txt). cargo
# produces the binary; rustc's link takes that archive and everything it
# depends on as linker arguments. Corrosion (external/corrosion, vendored
# and pinned, `add_subdirectory` only: gitian and depends build offline,
# so no FetchContent) is the bridge: it imports the crate as a CMake
# executable target named `shekyld`, runs `cargo rustc` under its own
# target directory inside this build directory, and copies the binary to
# `RUNTIME_OUTPUT_DIRECTORY`. Ruled temporary (DC-Q23): it goes when the
# last C++ archive does.
#
# Corrosion does not follow a library's dependencies. The closure walk
# that turns `shekyld_remnant`'s LINK_LIBRARIES into linker arguments is
# `shekyl_rust_link_cxx_closure` below, run at the end of configure, once
# every target it names exists.
#
# Flags reach rustc only through `corrosion_add_target_local_rustflags`,
# never `corrosion_add_target_rustflags`: the latter sets RUSTFLAGS, which
# replaces rust/.cargo/config.toml's `+crt-static` for the MSVC targets.
# scripts/ci/check_rt_p4_standing.py reads this file; a `-C` here is a
# `link-arg=`.

# The toolchain is rust/rust-toolchain.toml's. FindRust would otherwise
# resolve the rustup proxy to whichever toolchain is the default where
# CMake runs and hand cargo that concrete `rustc`, bypassing the pin. Left
# unresolved, Corrosion runs the proxies with the workspace as the working
# directory, which is what every other cargo invocation in this file does.
set(Rust_RESOLVE_RUSTUP_TOOLCHAINS OFF CACHE BOOL
    "Shekyl: cargo and rustc are rustup's proxies, so rust/rust-toolchain.toml selects the toolchain" FORCE)
if(RUST_TARGET_TRIPLE)
    set(Rust_CARGO_TARGET "${RUST_TARGET_TRIPLE}")
endif()
add_subdirectory("${CMAKE_SOURCE_DIR}/external/corrosion" "${CMAKE_BINARY_DIR}/external/corrosion")

# `RUST_PROFILE` names cargo's output directory (`debug`), Corrosion names
# the profile (`dev`). One choice, spelled for each.
if(RUST_PROFILE STREQUAL "release")
    set(_shekyld_cargo_profile "release")
else()
    set(_shekyld_cargo_profile "dev")
endif()

corrosion_import_crate(
    MANIFEST_PATH "${RUST_SOURCE_DIR}/Cargo.toml"
    CRATES shekyld
    LOCKED
    PROFILE "${_shekyld_cargo_profile}"
)

# The same environment the other cargo invocations get, except what
# Corrosion owns: the target directory (it passes `--target-dir`) and the
# linker (it selects the C++ driver when a linked library's language is
# CXX, which `shekyld_remnant`'s is). The cross link arguments that the
# other invocations carry as `CARGO_TARGET_<T>_RUSTFLAGS` are local
# rustflags here, below. `SHEKYL_CMAKE_LINK` tells rust/shekyld/build.rs
# this is the build that links; a bare `cargo build -p shekyld` warns
# instead. The build identity (DC-Q20) is the one the wallet binaries get.
set(_shekyld_env ${_rust_env_clear})
list(FILTER _shekyld_env EXCLUDE REGEX "^CARGO_TARGET_")
list(APPEND _shekyld_env
    "SHEKYL_CMAKE_LINK=1"
    "SHEKYL_VERSION_FULL=${SHEKYL_VERSION_FULL}"
    "SHEKYL_RELEASE_NAME=${SHEKYL_RELEASE_NAME}"
    "SHEKYL_VERSION_IS_RELEASE=${SHEKYL_VERSION_IS_RELEASE}"
)
corrosion_set_env_vars(shekyld ${_shekyld_env})

if(_rust_link_args)
    separate_arguments(_shekyld_cross_link_flags NATIVE_COMMAND "${_rust_link_args}")
    corrosion_add_target_local_rustflags(shekyld ${_shekyld_cross_link_flags})
endif()

# The executable link flags the C++ executables get from
# CMAKE_EXE_LINKER_FLAGS: the hardening set, the static-runtime set, and
# the strip. Not the MSVC `/STACK` and not MinGW's `--stack`: those sized
# the C++ main thread, and the remnant now runs on a thread
# shekyl-daemon spawns with an explicit stack (run.rs, §3.5). rustc's own
# defaults already produce PIE, full RELRO and BIND_NOW on the ELF
# targets; passing the C++ set as well keeps one list of record, and
# scripts/ci/check_binary_hardening.sh asserts the result on the binary.
if(NOT MSVC)
    separate_arguments(_shekyld_exe_link_flags NATIVE_COMMAND "${LD_SECURITY_FLAGS} ${STATIC_FLAGS}")
    foreach(_flag IN LISTS _shekyld_exe_link_flags)
        corrosion_add_target_local_rustflags(shekyld "-Clink-arg=${_flag}")
    endforeach()
    if(STRIP_TARGETS)
        corrosion_add_target_local_rustflags(shekyld "-Clink-arg=-s")
    endif()
endif()

# The measurement build only (Rick, 2026-10-14, extended for step 7): the
# Tor gap deadline lifted to 120 s, and the clearnet message-size tap.
# Never on in a release build; scripts/ci/check_measurement_spans.py fails
# any release path that sets it. Clearnet's feature is empty — it does not
# enable the transport-layer feature — and both names sit on this one
# line. Corrosion builds under this build directory's own cargo target
# directory, so the measurement binary can never be the file another
# build directory of the same checkout links.
option(SHEKYL_MEASUREMENT_SPANS "Measurement build only: lift the Tor gap to 120 s and record Levin message sizes" OFF)
if(SHEKYL_MEASUREMENT_SPANS)
    corrosion_set_features(shekyld FEATURES shekyl-transport-layer/measurement-spans shekyl-clearnet/measurement-spans)
    message(WARNING "SHEKYL_MEASUREMENT_SPANS is ON: this daemon is a measurement build, not a release")
endif()

# Where the C++ executables land (src/CMakeLists.txt); Corrosion appends
# the configuration directory on a multi-config generator the way CMake
# does for its own executables.
set_target_properties(shekyld PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
# The staged binary's path, for build steps that read it (the nm gate in
# src/daemon/CMakeLists.txt). Those steps hang off `cargo-build_shekyld`,
# and `$<TARGET_FILE:shekyld>` there would make that target depend on
# `shekyld`, which depends on `cargo-build_shekyld`: a cycle CMake
# refuses. A spelled-out path carries no target dependency.
if(CMAKE_CONFIGURATION_TYPES)
    set(SHEKYLD_STAGED_BINARY "${CMAKE_BINARY_DIR}/bin/$<CONFIG>/shekyld${CMAKE_EXECUTABLE_SUFFIX}")
else()
    set(SHEKYLD_STAGED_BINARY "${CMAKE_BINARY_DIR}/bin/shekyld${CMAKE_EXECUTABLE_SUFFIX}")
endif()

# shekyl_rust_link_cxx_closure(<rust_target> <cxx_target>)
#
# Hands the Rust binary <rust_target> the link closure of the C++ static
# library <cxx_target>: the library itself, every library it links,
# recursively, and the flags among them. Corrosion's
# `corrosion_link_libraries` takes one library and follows nothing, so a
# walk is needed; this is it. Each item of LINK_LIBRARIES and
# INTERFACE_LINK_LIBRARIES is classified, and anything that fits no class
# stops configure by name. The post-link nm gate is the backstop for what
# a wrong classification would let through, not the check.
#
# Classes:
#   - a first-party or imported target: its link file, recursed into
#     (an INTERFACE library has no file: recursed only);
#   - `shekyl_ffi`: dropped — its symbols are the rlibs already in the
#     link, and a second copy splits the tracing dispatcher;
#   - `$<LINK_ONLY:x>`: x (CMake's spelling of a static library's PRIVATE
#     dependency in its interface);
#   - an absolute path: itself;
#   - a flag (`-framework Security`, `-pthread`): itself, split on spaces;
#   - a plain name: `-l<name>` (`<name>.lib` on MSVC).
#
# Every argument is a `-C link-arg`, so it lands after rustc's own
# objects and rlibs. The two sides reference each other (DC-F20): the
# Rust side calls `core_rpc_ffi_*` and `shekyl_rpc_*`, the C++ side calls
# the `shekyl_*` exports. link.exe and ld64 resolve a cycle on their own;
# GNU ld walks archives once in order. Two measures for ld: the C++
# closure is one `--start-group … --end-group`, so the archives resolve
# among themselves whatever their order; and `--undefined-glob=shekyl_*`
# makes ld extract every member defining a `shekyl_*` symbol as it scans
# the rlibs, before the C++ archives ask for them. Every C-visible export
# of the Rust side is `shekyl_*` (scripts/ci/check_ffi_signatures.sh), so
# the glob is exact; a C++ `shekyl_remnant_*` matches too, harmlessly.
#
# Call it with `cmake_language(DEFER DIRECTORY ${CMAKE_SOURCE_DIR} CALL …)`
# from the directory that defines <cxx_target>, so it runs after every
# subdirectory has defined the targets the closure names.
function(shekyl_rust_link_cxx_closure rust_target cxx_target)
    if(NOT TARGET "${rust_target}")
        message(FATAL_ERROR "shekyl_rust_link_cxx_closure: no Rust target ${rust_target}")
    endif()
    if(NOT TARGET "${cxx_target}")
        message(FATAL_ERROR "shekyl_rust_link_cxx_closure: no C++ target ${cxx_target}")
    endif()

    set(_pending "${cxx_target}")
    set(_seen "")
    set(_args "")
    set(_cmake_targets "")
    while(_pending)
        list(POP_FRONT _pending _item)
        if("${_item}" STREQUAL "")
            continue()
        endif()
        # `$<LINK_ONLY:x>` → x; any other generator expression has no
        # classification here.
        if(_item MATCHES "^\\$<LINK_ONLY:(.*)>$")
            set(_item "${CMAKE_MATCH_1}")
        elseif(_item MATCHES "\\$<")
            message(FATAL_ERROR
                "shekyl_rust_link_cxx_closure: generator expression in ${cxx_target}'s closure "
                "cannot be classified: ${_item}")
        endif()
        if("${_item}" IN_LIST _seen)
            continue()
        endif()
        list(APPEND _seen "${_item}")

        if("${_item}" STREQUAL "shekyl_ffi")
            continue()
        elseif(TARGET "${_item}")
            get_target_property(_aliased "${_item}" ALIASED_TARGET)
            if(_aliased)
                list(APPEND _pending "${_aliased}")
                continue()
            endif()
            get_target_property(_type "${_item}" TYPE)
            get_target_property(_imported "${_item}" IMPORTED)
            if(_type STREQUAL "INTERFACE_LIBRARY")
                # headers and flags only; its interface may name libraries
            elseif(_type STREQUAL "STATIC_LIBRARY" OR _type STREQUAL "SHARED_LIBRARY"
                    OR _type STREQUAL "UNKNOWN_LIBRARY" OR _type STREQUAL "MODULE_LIBRARY")
                list(APPEND _args "-Clink-arg=$<TARGET_LINKER_FILE:${_item}>")
                if(NOT _imported)
                    list(APPEND _cmake_targets "${_item}")
                endif()
            elseif(_type STREQUAL "OBJECT_LIBRARY")
                message(FATAL_ERROR
                    "shekyl_rust_link_cxx_closure: ${_item} is an OBJECT library; its objects "
                    "would need listing one by one, which this walk does not do")
            else()
                message(FATAL_ERROR
                    "shekyl_rust_link_cxx_closure: ${_item} is a ${_type}, not a library")
            endif()
            foreach(_prop IN ITEMS LINK_LIBRARIES INTERFACE_LINK_LIBRARIES)
                if(_imported AND _prop STREQUAL "LINK_LIBRARIES")
                    continue()
                endif()
                get_target_property(_deps "${_item}" "${_prop}")
                if(_deps)
                    list(APPEND _pending ${_deps})
                endif()
            endforeach()
        elseif(IS_ABSOLUTE "${_item}")
            list(APPEND _args "-Clink-arg=${_item}")
        elseif(_item MATCHES "^-")
            separate_arguments(_words NATIVE_COMMAND "${_item}")
            foreach(_word IN LISTS _words)
                list(APPEND _args "-Clink-arg=${_word}")
            endforeach()
        elseif(_item MATCHES "^[A-Za-z0-9_.+-]+$")
            if(MSVC)
                list(APPEND _args "-Clink-arg=${_item}.lib")
            else()
                list(APPEND _args "-Clink-arg=-l${_item}")
            endif()
        else()
            message(FATAL_ERROR
                "shekyl_rust_link_cxx_closure: item in ${cxx_target}'s closure cannot be "
                "classified: ${_item}")
        endif()
    endwhile()

    if(NOT _args)
        message(FATAL_ERROR "shekyl_rust_link_cxx_closure: ${cxx_target}'s closure is empty")
    endif()

    # GNU ld: Linux and FreeBSD with the GNU toolchain, and MinGW. lld,
    # ld64 and link.exe accept or need neither; `--start-group` is a
    # no-op to lld, an error to ld64.
    set(_gnu_ld OFF)
    if(CMAKE_SYSTEM_NAME MATCHES "^(Linux|FreeBSD)$" OR (CMAKE_SYSTEM_NAME STREQUAL "Windows" AND NOT MSVC))
        set(_gnu_ld ON)
    endif()
    if(_gnu_ld)
        list(PREPEND _args "-Clink-arg=-Wl,--start-group")
        list(APPEND _args "-Clink-arg=-Wl,--end-group" "-Clink-arg=-Wl,--undefined-glob=shekyl_*")
    endif()

    corrosion_add_target_local_rustflags("${rust_target}" ${_args})
    # The language decides the linker driver Corrosion selects (the C++
    # one for CXX). `corrosion_link_libraries` would record it from the
    # one library it is given; the walk records it from the root.
    get_target_property(_lang "${cxx_target}" LINKER_LANGUAGE)
    if(NOT _lang)
        set(_lang CXX)
    endif()
    set_property(TARGET "_cargo-build_${rust_target}" APPEND PROPERTY CARGO_DEPS_LINKER_LANGUAGES "${_lang}")
    # Every first-party archive exists before cargo links.
    add_dependencies("cargo-prebuild_${rust_target}" ${_cmake_targets})

    list(LENGTH _args _count)
    message(STATUS "${rust_target} links ${cxx_target}'s closure: ${_count} linker arguments")
endfunction()

# ── Rust user-facing binaries (shekyl-cli, shekyl-wallet-rpc) ────────────────
#
# C1/C2 install cutover. Until this landed, `cargo` was invoked here only for
# the two staticlibs, so the CMake build produced no wallet binaries at all:
# `shekyl-wallet-rpc` in `bin/` was the C++ `wallet_rpc_server` wearing that
# OUTPUT_NAME, and `shekyl-cli` — which INSTALLATION_GUIDE.md has always
# listed as a build output — did not exist.
#
# The binaries are built and staged here, not in `src/wallet/CMakeLists.txt`,
# because that file was deleted wholesale with wallet2 at Phase 5: install
# rules parked there would have had to be re-cut by that commit.
#
# Staging into `${CMAKE_BINARY_DIR}/bin` is load-bearing beyond developer
# convenience: contrib/gitian/gitian-*.yml does not run `make install`, it
# tars whatever `bin/` holds, so this copy is what puts the binaries into the
# release archives.
#
# NOT built for Windows — but no longer for the reason this comment used to
# give, and the difference matters to anyone deciding whether to flip the line.
#
# The original rationale said the Rust wallet stack was Unix-only, that a
# Windows port was an unanswered design question (named-pipe ACLs vs. UDS), and
# that building here would fail on the first of many such sites. All three are
# now false. WP-Q1 ruled the named pipe, WP-W2 shipped it, `shekyl-win-sec` IS
# the named-pipe ACL half, and on 2026-08-25 both binaries were observed to
# build and link for `x86_64-pc-windows-msvc` on a Windows box
# (`cargo build --locked -p shekyl-cli -p shekyl-wallet-rpc --bins`, exit 0),
# with `shekyl-cli`'s `rpc_session_e2e` passing there. A comment naming as an
# open blocker the exact thing a completed round closed is the drift this repo
# keeps finding.
#
# What is still unverified is everything between "the binaries compile" and
# "the release archive contains a working wallet": this CMake path itself
# (which cross-compiles with its own target/linker wiring, not the host cargo
# build that was observed), staging into `bin/`, `install()`, and the archive
# layout. Compiling is not installing. So the skip stays until WP-W5 removes
# it deliberately, together with the CI job that builds and smoke-tests both
# binaries — see docs/FOLLOWUPS.md "Rust wallet stack: no Windows support" and
# `WINDOWS_WALLET_SUPPORT.md` §8. Flipping this line on the strength of a
# `cargo build` alone would be exactly the half-ported wallet the original
# rationale was right to refuse.
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows" AND NOT IOS)
    set(_shekyl_rust_bins shekyl-cli shekyl-wallet-rpc)

    # Match where the C++ executables land (src/CMakeLists.txt sets
    # RUNTIME_OUTPUT_DIRECTORY to ${CMAKE_BINARY_DIR}/bin, which multi-config
    # generators suffix with the config).
    if(CMAKE_CONFIGURATION_TYPES)
        set(_shekyl_rust_bin_dir "${CMAKE_BINARY_DIR}/bin/$<CONFIG>")
    else()
        set(_shekyl_rust_bin_dir "${CMAKE_BINARY_DIR}/bin")
    endif()

    set(_shekyl_rust_bin_pkg_args "")
    set(_shekyl_rust_bin_outputs "")
    set(_shekyl_rust_bin_staged "")
    foreach(_bin IN LISTS _shekyl_rust_bins)
        list(APPEND _shekyl_rust_bin_pkg_args -p "${_bin}")
        list(APPEND _shekyl_rust_bin_outputs
            "${RUST_BUILD_DIR}/${_bin}${CMAKE_EXECUTABLE_SUFFIX}")
        list(APPEND _shekyl_rust_bin_staged
            "${_shekyl_rust_bin_dir}/${_bin}${CMAKE_EXECUTABLE_SUFFIX}")
    endforeach()

    # The binaries print the build identity (`SHEKYL_VERSION_FULL`,
    # `SHEKYL_RELEASE_NAME`, `SHEKYL_VERSION_IS_RELEASE`, spelled once in
    # cmake/Version.cmake and read by `rust/shekyl-version`; DC-Q20), not
    # the crate's `3.1.0`. This target runs on every build. Cargo
    # fingerprints `option_env!` and compiles only when a value or a source
    # changed. An OUTPUT rule would not: a later bare `cargo build` of these
    # packages writes `-unknown` binaries over the same paths, newer than
    # every DEPENDS file, and the next CMake build would skip cargo and
    # stage those.
    add_custom_target(shekyl_rust_bins ALL
        COMMAND ${CMAKE_COMMAND} -E env ${_rust_env_clear}
            "SHEKYL_VERSION_FULL=${SHEKYL_VERSION_FULL}"
            "SHEKYL_RELEASE_NAME=${SHEKYL_RELEASE_NAME}"
            "SHEKYL_VERSION_IS_RELEASE=${SHEKYL_VERSION_IS_RELEASE}"
            ${CARGO_EXECUTABLE} build --locked ${RUST_BUILD_FLAG} ${RUST_TARGET_FLAG}
            ${_shekyl_rust_bin_pkg_args}
        WORKING_DIRECTORY ${RUST_SOURCE_DIR}
        COMMENT "${_rust_comment} (shekyl-cli + shekyl-wallet-rpc binaries)"
        VERBATIM
    )

    # POST_BUILD re-copies into `bin/` on every build. `copy_if_different`
    # is a stat in the common case. Deleting `bin/` (or a generator
    # `clean`) would otherwise leave the staged copies missing while
    # cargo's own artifacts were still present, and release packaging
    # and the CI smoke tests read `bin/`.
    add_custom_command(TARGET shekyl_rust_bins POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${_shekyl_rust_bin_dir}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${_shekyl_rust_bin_outputs} "${_shekyl_rust_bin_dir}"
        VERBATIM
    )

    # Install the STAGED copies, not the cargo target directory, so there is
    # exactly one answer to "which binary is this release" — the same file
    # gitian tars. PROGRAMS, not FILES: it sets the executable bit.
    #
    # Note the Rust profile is chosen at configure time from
    # CMAKE_BUILD_TYPE (see RUST_PROFILE above) and is therefore shared by
    # every config a multi-config generator builds. That predates this block
    # — SHEKYL_FFI_LIBRARY resolves the same way — so it is left alone here
    # rather than fixed for the binaries only, which would leave the
    # staticlibs and the binaries disagreeing about what `--config` means.
    install(PROGRAMS ${_shekyl_rust_bin_staged} DESTINATION bin)
endif()
