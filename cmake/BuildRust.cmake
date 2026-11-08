# Copyright (c) 2025-2026, The Shekyl Foundation
# BuildRust.cmake -- Integrate Cargo workspace into CMake build
#
# One cargo product: the Rust binaries — the daemon `shekyld`
# (DAEMON_CONFIG_CUTOVER.md DC-Q19) and the wallet binaries `shekyl-cli` and
# `shekyl-wallet-rpc`. Supports native builds and cross-compilation
# (detected via CMAKE_SYSTEM_NAME).

find_program(CARGO_EXECUTABLE cargo HINTS "$ENV{HOME}/.cargo/bin")

if(NOT CARGO_EXECUTABLE)
    message(STATUS "Cargo not found -- Rust modules will not be built")
    set(SHEKYL_RUST_ENABLED OFF CACHE INTERNAL "Whether Rust workspace build is enabled" FORCE)
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
    # The binaries this file stages are read from ${RUST_BUILD_DIR}, under
    # the workspace's own target directory. cargo builds wherever
    # CARGO_TARGET_DIR points, so a shell that exports it for Rust work would
    # otherwise build the fresh binaries elsewhere while the staging step
    # copies whatever stale ones sit at the read path, and nothing would say
    # so. The variable is pinned here to the path the staging reads.
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
        # that binary's floor from the 10.15 it ships at to 11.0,
        # dropping macOS versions still supported elsewhere in the build.
        # On arm64 it costs nothing, 11.0 being the floor already.
        if(RUST_TARGET_TRIPLE STREQUAL "aarch64-apple-darwin")
            string(APPEND _rust_link_args " -C link-arg=-mmacosx-version-min=10.16")
        endif()

        # The stack protector's runtime on mingw. The forwarded flags compile
        # the C inside crates (ring) with `-fstack-protector-strong` and
        # `_FORTIFY_SOURCE`, whose `__stack_chk_fail`, `__stack_chk_guard` and
        # `__*_chk` live in libssp there, not in the C runtime. gcc adds
        # libssp itself when it sees those flags at link, but only from the
        # default-libraries part of its spec, and rustc always links with
        # `-nodefaultlibs`. A CMake link of the same objects had no such
        # switch, which is why this surfaced only once `shekyld` became an
        # all-cargo link. Static, so the binary needs no libssp DLL beside
        # it. What libssp itself calls follows it, because GNU ld does not go
        # back to libraries it already passed: msvcrt (write, open, the
        # string functions), advapi32 (the CryptoAPI calls that seed the
        # guard) and libgcc (___chkstk_ms). gcc's own mingw LIB_SPEC orders
        # them the same way. Checked against Ubuntu 22.04's mingw-w64 8.0.0
        # archives, whose C runtime defines none of these symbols.
        if(RUST_TARGET_TRIPLE MATCHES "-windows-gnu$" AND _target_cflags MATCHES "-fstack-protector")
            string(APPEND _rust_link_args
                " -C link-arg=-l:libssp.a -C link-arg=-lmsvcrt -C link-arg=-ladvapi32 -C link-arg=-lgcc")
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

#
# ── Rust binaries: shekyld, shekyl-cli, shekyl-wallet-rpc ───────────────────
#
# `shekyld` is a Rust binary (DC-Q19) with no C++ in its link since the p2p
# remnant cutover (P2P_3_REMNANT_CUTOVER_BRIEF.md §1): cargo builds it like
# the wallet binaries below, and the Corrosion bridge that handed rustc the
# C++ archives went with the last of them (DC-Q23 ruled it temporary for
# exactly that long). Its hardening is rustc's own defaults — PIE, full
# RELRO and BIND_NOW on the ELF targets — which
# scripts/ci/check_binary_hardening.sh asserts on the staged file.
#
# C1/C2 install cutover. Until this landed, `cargo` was invoked here only for
# the two staticlibs, so the CMake build produced no wallet binaries at all:
# `shekyl-wallet-rpc` in `bin/` was the C++ `wallet_rpc_server` wearing that
# OUTPUT_NAME, and `shekyl-cli` — which INSTALLATION_GUIDE.md has always
# listed as a build output — did not exist.
#
# Staging into `${CMAKE_BINARY_DIR}/bin` is load-bearing beyond developer
# convenience: contrib/gitian/gitian-*.yml does not run `make install`, it
# tars whatever `bin/` holds, so this copy is what puts the binaries into the
# release archives.
#
# The wallet binaries are NOT built for Windows — but no longer for the
# reason this comment used to give, and the difference matters to anyone
# deciding whether to flip the line.
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
# rationale was right to refuse. The daemon is built everywhere.
if(NOT IOS)
    if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        set(_shekyl_rust_bins shekyld)
    else()
        set(_shekyl_rust_bins shekyld shekyl-cli shekyl-wallet-rpc)
    endif()

    # Staged in ${CMAKE_BINARY_DIR}/bin, which multi-config generators
    # suffix with the config.
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

    # The measurement build only (Rick, 2026-10-14, extended for step 7 and
    # the remnant cutover's fleet run): the Tor gap deadline lifted to 120 s,
    # the clearnet message-size tap, and the relay's transaction ids on its
    # debug lines. Never on in a release build;
    # scripts/ci/check_measurement_spans.py fails any release path that sets
    # it. The clearnet and relay features are empty — neither enables another
    # — and all three names sit on this one line. The features are the
    # daemon's: cargo unifies them across the packages of one invocation, and
    # the wallet binaries depend on none of the crates, so the line changes
    # nothing they link.
    option(SHEKYL_MEASUREMENT_SPANS "Measurement build only: lift the Tor gap to 120 s, record Levin message sizes, name relayed transactions in debug lines" OFF)
    set(_shekyl_rust_bin_features "")
    if(SHEKYL_MEASUREMENT_SPANS)
        set(_shekyl_rust_bin_features --features shekyl-transport-layer/measurement-spans,shekyl-clearnet/measurement-spans,shekyl-relay/measurement-spans)
        message(WARNING "SHEKYL_MEASUREMENT_SPANS is ON: this daemon is a measurement build, not a release")
    endif()

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
            ${_shekyl_rust_bin_pkg_args} ${_shekyl_rust_bin_features}
        WORKING_DIRECTORY ${RUST_SOURCE_DIR}
        COMMENT "${_rust_comment} (shekyld, shekyl-cli and shekyl-wallet-rpc binaries)"
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
    # every config a multi-config generator builds.
    install(PROGRAMS ${_shekyl_rust_bin_staged} DESTINATION bin)
endif()
