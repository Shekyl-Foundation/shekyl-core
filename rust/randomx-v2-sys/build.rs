// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Phase 2g `randomx-v2-sys` linker glue.
//
// Emits the `cargo:rustc-link-{search,lib}` directives that point the
// Rust toolchain at the C reference library produced by
// `external/randomx-v2`'s `ExternalProject_Add` (landed at C2 per
// `docs/design/RANDOMX_V2_PHASE2G_PLAN.md` §5.4.2). The handoff between
// the C build (CMake-driven, gated on
// `BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS`) and this Rust build
// (Cargo-driven, gated on the `RANDOMX_V2_INSTALL_DIR` environment
// variable) is the substrate that R4-D3 (§3.16) closes against and
// R5-D2 (§3.17) refines.
//
// Behavior summary (per §5.2.2 + R5-D2 + §3.18 R6-D3):
//
//   - Always emit `cargo:rerun-if-env-changed=RANDOMX_V2_INSTALL_DIR`
//     so subsequent `cargo` invocations re-evaluate env-var presence
//     without requiring `cargo clean`.
//
//   - When `RANDOMX_V2_INSTALL_DIR` is set: emit
//     `cargo:rustc-link-search=native={dir}/lib` and
//     `cargo:rustc-link-lib=static=randomx` so the downstream
//     `shekyl-randomx-differential` binary's link step finds
//     `librandomx.a`. The link-lib name is the on-disk filename
//     (`librandomx.a`), **not** the CMake imported-target name
//     `shekyl_randomx_v2` — R4-D2 (§3.16) is explicit on this.
//
//   - The C reference is a C++ static archive; downstream binary
//     links need the host C++ runtime to resolve `__cxa_*`,
//     `operator new`, `std::__cxx11::basic_string`, etc. The C++
//     runtime is platform-specific (`stdc++` on GNU/Linux, `c++` on
//     macOS, MSVC runtime on Windows); §3.18 R6-D3 documents this
//     substrate-correction. Per the workspace's CI matrix (Linux +
//     macOS for the harness; Windows out-of-scope for Phase 2g),
//     `target_os` is matched to emit the correct runtime link
//     directive. Without this, the binary link step fails with ~50
//     "undefined symbol" errors against the C++ runtime — surfaced
//     at C5a binary-build time.
//
//   - When `RANDOMX_V2_INSTALL_DIR` is unset: emit a `cargo:warning=…`
//     naming the env var, the
//     `-DBUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=ON` cmake option, and
//     the handoff relationship between the two, then `return`
//     cleanly. The `rlib` still compiles; only the downstream binary
//     link step fails (with undefined references to the seven cache
//     + VM symbols enumerated in `src/lib.rs`). This is the R5-D2
//     soft-fail refinement of R4-D3's original `process::exit(1)`
//     disposition; it preserves the §8 per-commit bisection invariant
//     for workspace-wide cargo invocations (e.g., `cargo clippy
//     --workspace`) that compile every `build.rs` regardless of
//     whether a downstream binary is being linked.

use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=RANDOMX_V2_INSTALL_DIR");

    match env::var("RANDOMX_V2_INSTALL_DIR") {
        Ok(dir) => {
            println!("cargo:rustc-link-search=native={dir}/lib");
            println!("cargo:rustc-link-lib=static=randomx");
            // §3.18 R6-D3: librandomx.a is a C++ static archive;
            // downstream binary links require the host C++ runtime.
            // Platform-specific because the runtime library name
            // differs by toolchain (GNU/libstdc++ vs. LLVM/libc++).
            let cxx_runtime = match env::var("CARGO_CFG_TARGET_OS").as_deref() {
                Ok("macos" | "ios" | "freebsd" | "openbsd") => "c++",
                _ => "stdc++",
            };
            println!("cargo:rustc-link-lib=dylib={cxx_runtime}");
        }
        Err(_) => {
            println!(
                "cargo:warning=RANDOMX_V2_INSTALL_DIR not set; \
                 randomx-v2-sys's rlib will compile but linking any \
                 binary that depends on it (e.g., the Phase 2g \
                 shekyl-randomx-differential harness) will fail with \
                 undefined references to the 7-symbol cache + VM \
                 surface. To build the harness: configure CMake with \
                 -DBUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=ON, build \
                 the librandomx.a artifact, then export \
                 RANDOMX_V2_INSTALL_DIR pointing to the install \
                 prefix (typically \
                 <build-dir>/external/randomx-v2-install) \
                 before running cargo. See \
                 docs/design/RANDOMX_V2_PHASE2G_PLAN.md §3.16 R4-D3 + \
                 §3.17 R5-D2 + §5.2.2."
            );
        }
    }
}
