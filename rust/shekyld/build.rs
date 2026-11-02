// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `shekyld` links the C++ remnant's archives, which only CMake builds and
//! only CMake (through Corrosion) hands to this crate's link. A bare
//! `cargo build -p shekyld` reaches the link with no `shekyl_remnant_run`
//! and fails there; this script says why before it does. CMake sets
//! `SHEKYL_CMAKE_LINK` on the crate's environment (`cmake/BuildRust.cmake`),
//! so the line is printed only outside it. `cargo check`, `clippy` and
//! `test` never link the binary and need nothing from CMake.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SHEKYL_CMAKE_LINK");
    if std::env::var_os("SHEKYL_CMAKE_LINK").is_none() {
        println!(
            "cargo:warning=shekyld links the C++ remnant only through CMake \
             (`cmake --build <dir> --target cargo-build_shekyld`); a bare cargo build of \
             this binary stops at the link with `shekyl_remnant_run` undefined"
        );
    }
}
