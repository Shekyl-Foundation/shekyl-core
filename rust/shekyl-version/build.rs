// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The build identity reaches this crate through three environment
//! variables `cmake/Version.cmake` sets on every cargo invocation
//! (`DAEMON_CONFIG_CUTOVER.md` DC-Q20). `option_env!` reads them at compile
//! time; this script tells cargo to recompile the crate when any of them
//! changes, so a configure that moves the version tag is not served a stale
//! constant from the cache.

fn main() {
    for name in [
        "SHEKYL_VERSION_FULL",
        "SHEKYL_RELEASE_NAME",
        "SHEKYL_VERSION_IS_RELEASE",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
