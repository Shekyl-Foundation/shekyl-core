# The release build is Rust, which cargo builds; depends supplies only the
# C toolchain that cargo's build scripts (cc) and its linker step use for a
# cross target. macOS takes its SDK, clang, cctools and libtapi from here;
# FreeBSD takes its base system as the sysroot. Linux and Windows (MinGW)
# take their compilers from the build image's packages, so they need none.
packages :=

darwin_native_packages =
ifneq ($(build_os),darwin)
darwin_native_packages += darwin_sdk native_clang native_cctools native_libtapi
endif

# Not a native tool: the target's base system, used as the sysroot.
freebsd_native_packages = freebsd_base
